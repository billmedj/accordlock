import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import type { Writable } from 'node:stream';
import {
  accordLockApprovalProxyRequestLimit,
  accordLockApprovalProxyResponseLimit,
  type AccordLockApprovalProxyResponse,
  type AccordLockRuntimeMethod,
  type AccordLockRuntimePath,
} from './accordlockApprovalProxy';
import type { AccordLockTerminalProgramBinding } from './accordlockTerminalPrograms';

export const ACCORDLOCK_RUNTIME_URL_ENV = 'ACCORDLOCK_RUNTIME_URL';
export const ACCORDLOCK_RUNTIME_TOKEN_ENV = 'ACCORDLOCK_RUNTIME_TOKEN';
export const ACCORDLOCK_GOVERNED_NETWORK_ENV = 'ACCORDLOCK_GOVERNED_NETWORK';
export const ACCORDLOCK_RUNTIME_MARKER_FILENAME = 'accordlock-runtime-build.json';
export const ACCORDLOCK_RUNTIME_READY_PREFIX = 'ACCORDLOCK_RUNTIME_READY=';
export const ACCORDLOCK_CONTROL_FRAME_MAGIC = 'ALC1';
export const ACCORDLOCK_CONTROL_MAX_FRAME_BYTES = 256 * 1_024;

const RUNTIME_COMPONENT = 'accordlock-agent-runtime';
const RUNTIME_DISTRIBUTION = 'AccordLock';
const RUNTIME_BUILD_MARKER_SCHEMA_VERSION = 2;
const RUNTIME_PROTOCOL_VERSION = 2;
const RUNTIME_HEALTH_PATH = '/api/v2/health';
const NETWORK_EXECUTION_PATH = '/api/v2/execution/network/authorize-and-execute';
const TERMINAL_EXECUTION_PATH = '/api/v2/execution/terminal/authorize-and-execute';
const TOKEN_BYTES = 32;
const MAX_READY_LINE_BYTES = 4_096;
const MAX_HEALTH_RESPONSE_BYTES = 4_096;
const DEFAULT_STARTUP_TIMEOUT_MS = 15_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 5_000;
const DEFAULT_CONTROL_REQUEST_TIMEOUT_MS = 10_000;
const NETWORK_EXECUTION_REQUEST_TIMEOUT_MS = 150_000;
const TERMINAL_EXECUTION_REQUEST_TIMEOUT_MS = 330_000;
const MAX_APPROVAL_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const MAX_CAPABILITIES = 256;
const MAX_AUTOMATIC_CAPABILITIES = 16;
const MAX_PROTECTED_PATHS = 256;
const MAX_REVIEW_RELATIVE_PATH_BYTES = 4 * 1_024;
const MAX_ACTION_APPROVAL_LIFETIME_SECONDS = 5 * 60;
const APPROVED_SESSION_SCHEMA_VERSION = 3;
const TASK_POLICY_SCHEMA_VERSION = 2;
const TASK_POLICY_DIGEST_DOMAIN = 'accordlock:v2:task-policy';
const FILE_RESTORE_CHALLENGE_DIGEST_DOMAIN = Buffer.from(
  'accordlock:v2:file-restore-challenge\0',
  'ascii'
);
const FILE_RESTORE_RECORD_DIGEST_DOMAIN = Buffer.from(
  'accordlock:v2:file-restore-record\0',
  'ascii'
);
const SESSION_AUDIT_PAGE_SCHEMA_VERSION = 6 as const;
const SESSION_AUDIT_PAGE_DIGEST_DOMAIN = Buffer.from('accordlock:v6:session-audit-page\0', 'ascii');
const RUNTIME_OS_ENV_ALLOWLIST = [
  'SystemRoot',
  'WINDIR',
  'TEMP',
  'TMP',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
] as const;

export interface AccordLockRuntimeBuildMarker {
  schema_version: 2;
  distribution: 'AccordLock';
  component: 'accordlock-agent-runtime';
  protocol_version: 2;
  source_commit: string;
  source_dirty: boolean;
  binary: string;
  binary_sha256: string;
}

export interface AccordLockRuntimeBundle {
  binaryPath: string;
  markerPath: string;
  marker: AccordLockRuntimeBuildMarker;
}

export interface RuntimeLogger {
  info: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
}

export interface AccordLockRuntimeExit {
  code: number | null;
  signal: ChildProcess['signalCode'];
}

export interface AccordLockRuntimeHandle {
  runtimeUrl: string;
  process: ChildProcess;
  authorizeTask: (approvedSession: ApprovedSession) => Promise<AccordLockAuthorizationRecord>;
  revokeSession: (revocation: SessionRevocation) => Promise<AccordLockRevocationRecord>;
  registerActionApproval: (
    actionApproval: AccordLockActionApproval
  ) => Promise<AccordLockActionApprovalRecord>;
  prepareFileRestore: (
    recoveryId: string
  ) => Promise<AccordLockFileRestorePreparation | AccordLockFileRestoreRecord>;
  commitFileRestore: (
    challenge: AccordLockFileRestoreChallenge
  ) => Promise<AccordLockFileRestoreRecord>;
  getSessionAudit: (
    sessionId: string,
    offset?: number,
    limit?: number,
    snapshotRevision?: number | null
  ) => Promise<AccordLockSessionAuditPage>;
  forwardPolicyRequest: (
    path: AccordLockRuntimePath,
    method: AccordLockRuntimeMethod,
    body: Uint8Array
  ) => Promise<AccordLockApprovalProxyResponse>;
  cleanup: () => Promise<void>;
  hasExited: () => boolean;
  getExitDetails: () => AccordLockRuntimeExit;
}

export interface AccordLockCapability {
  extension_id: string;
  tool_name: string;
}

export interface AccordLockTaskPolicy {
  schema_version: 2;
  task_objective_hash: string;
  preauthorized_capabilities: AccordLockCapability[];
  protected_paths: string[];
}

/** Exact authority record accepted by the trusted Rust control channel. */
export interface ApprovedSession {
  schema_version: 3;
  task_id: string;
  session_id: string;
  run_id: string;
  workspace_root: string;
  task_objective: string;
  policy_epoch: number;
  task_policy: AccordLockTaskPolicy;
  task_policy_hash: string;
  capabilities: AccordLockCapability[];
  approved_at: number;
  expires_at: number;
}

export interface AccordLockAuthorizationRecord {
  requestId: string;
  code: 'SESSION_APPROVED' | 'SESSION_ALREADY_APPROVED';
  approvalDigest: string;
}

/** Exact immutable authority identity accepted by `REVOKE_SESSION`. */
export interface SessionRevocation {
  schema_version: 2;
  task_id: string;
  session_id: string;
  run_id: string;
}

export interface AccordLockRevocationRecord {
  requestId: string;
  code: 'SESSION_REVOKED' | 'SESSION_ALREADY_REVOKED';
  revocationDigest: string;
  taskId: string;
  sessionId: string;
  runId: string;
}

export type AccordLockApprovalDecision = 'APPROVED' | 'DENIED';

/** Single-use human decision over one exact runtime-generated approval request. */
export interface AccordLockActionApproval {
  schema_version: 2;
  approval_id: string;
  task_id: string;
  session_id: string;
  run_id: string;
  tool_call_id: string;
  proposal_digest: string;
  task_policy_hash: string;
  prestate_hash: string;
  approval_request_hash: string;
  task_requirement: Readonly<Record<string, unknown>>;
  transformation_step: Readonly<Record<string, unknown>>;
  policy_decision: Readonly<Record<string, unknown>>;
  policy_decision_hash: string;
  decision: AccordLockApprovalDecision;
  approval_evidence_hash: string;
  decided_at: number;
  expires_at: number;
}

export interface AccordLockActionApprovalRecord {
  requestId: string;
  code: 'ACTION_APPROVAL_REGISTERED' | 'ACTION_APPROVAL_ALREADY_REGISTERED';
  approvalDigest: string;
  approvalId: string;
  proposalDigest: string;
  approvalRequestHash: string;
}

/** Runtime-generated, exact restore proposal. Renderer input can never supply these fields. */
export interface AccordLockFileRestoreChallenge {
  schema_version: 2;
  restore_id: string;
  recovery_id: string;
  task_id: string;
  session_id: string;
  run_id: string;
  original_record_id: string;
  original_record_hash: string;
  workspace_root: string;
  relative_path: string;
  content_sha256: string;
  original_bytes: number;
  prepared_at: number;
}

export interface AccordLockFileRestorePreparation {
  requestId: string;
  code: 'FILE_RESTORE_PREPARED' | 'FILE_RESTORE_ALREADY_PREPARED';
  challengeHash: string;
  challenge: AccordLockFileRestoreChallenge;
}

export interface AccordLockFileRestoreResult {
  schema_version: 2;
  restore_id: string;
  recovery_id: string;
  challenge_hash: string;
  task_id: string;
  session_id: string;
  run_id: string;
  original_record_id: string;
  original_record_hash: string;
  workspace_root: string;
  relative_path: string;
  content_sha256: string;
  original_bytes: number;
  completed_at: number;
}

export interface AccordLockFileRestoreRecord {
  requestId: string;
  code: 'FILE_RESTORE_COMMITTED' | 'FILE_RESTORE_ALREADY_COMMITTED';
  challengeHash: string;
  recordHash: string;
  record: AccordLockFileRestoreResult;
}

type AuditEventBase = {
  event_id: string;
  recorded_at: number;
};

export type AccordLockIntentFindingReason =
  | 'SUPPORTED'
  | 'MISSING_EVIDENCE'
  | 'INCONCLUSIVE_EVIDENCE'
  | 'UNVERIFIED_PROVENANCE'
  | 'EXPIRED_CALIBRATION'
  | 'CONFIDENCE_THRESHOLD_UNCERTAIN'
  | 'BELOW_THRESHOLD'
  | 'CONTRADICTORY_EVIDENCE'
  | 'SCOPE_MISMATCH'
  | 'EVIDENCE_CHAIN_MISMATCH'
  | 'LEDGER_SNAPSHOT_MISMATCH'
  | 'TRUST_POLICY_MISMATCH';

export interface AccordLockIntentAssessment {
  schema_version: 1;
  profile: 'PRE_EXECUTION' | 'COMPLETE_TRACE';
  status: 'VERIFIED' | 'REVIEW_REQUIRED' | 'BLOCKED';
  evidence_count: number;
  finding_reasons: AccordLockIntentFindingReason[];
}

export type AccordLockSessionAuditEvent =
  | (AuditEventBase & {
      type: 'SESSION_APPROVED';
      task_id: string;
      run_id: string;
      workspace_root: string;
      policy_hash: string;
      expires_at: number;
    })
  | (AuditEventBase & {
      type: 'SESSION_REVOKED';
      task_id: string;
      run_id: string;
      revocation_digest: string;
    })
  | (AuditEventBase & {
      type: 'ACTION_DECISION';
      approval_id: string;
      tool_call_id: string;
      proposal_digest: string;
      decision: AccordLockApprovalDecision;
      evidence_hash: string;
      consumed: boolean;
    })
  | (AuditEventBase & {
      type: 'ACTION_STARTED';
      authorization_id: string;
      tool_call_id: string;
      extension_id: string;
      tool_name: string;
      proposal_digest: string;
      request_hash: string;
      conformance_evaluation_hashes: string[];
      task_scope_status: 'WITHIN_APPROVED_ACCESS' | 'REVIEW_REQUIRED';
      review_status: 'NOT_REQUIRED' | 'APPROVED';
      decision_reason_code: 'POLICY_CONFORMANT' | 'ACTION_APPROVAL_ACCEPTED';
      task_control_hash: string;
      task_control_provenance: 'DECISION_BOUND';
      intent_evaluation_hash: string;
      intent_assessment: AccordLockIntentAssessment;
    })
  | (AuditEventBase & {
      type: 'ACTION_COMPLETED';
      authorization_id: string;
      tool_call_id: string;
      outcome: string;
      state: 'SUCCEEDED' | 'EXECUTION_UNKNOWN';
      record_hash: string | null;
      execution_lineage_hash: string;
      task_scope_status: 'WITHIN_APPROVED_ACCESS' | 'REVIEW_REQUIRED';
      review_status: 'NOT_REQUIRED' | 'APPROVED';
      decision_reason_code: 'POLICY_CONFORMANT' | 'ACTION_APPROVAL_ACCEPTED';
      task_control_hash: string;
      task_control_provenance: 'LINEAGE_BOUND' | 'EMBEDDED' | 'RECONSTRUCTED';
      intent_pre_evaluation_hash: string;
      intent_complete_evaluation_hash: string | null;
      intent_pre_assessment: AccordLockIntentAssessment;
      intent_complete_assessment: AccordLockIntentAssessment;
    })
  | (AuditEventBase & {
      type: 'ACTION_DENIED';
      denial_id: number;
      attempted_run_id: string;
      tool_call_id: string;
      proposal_digest: string;
      reason_code: string;
    })
  | (AuditEventBase & {
      type: 'RESTORE_PREPARED';
      restore_id: string;
      recovery_id: string;
      relative_path: string;
      content_hash: string;
    })
  | (AuditEventBase & {
      type: 'RESTORE_COMPLETED';
      restore_id: string;
      recovery_id: string;
      relative_path: string;
      record_hash: string;
    });

export interface AccordLockSessionAuditPage {
  schema_version: 6;
  task_id: string;
  session_id: string;
  run_id: string;
  offset: number;
  next_offset: number | null;
  total_events: number;
  snapshot_revision: number;
  snapshot_at: number;
  events: AccordLockSessionAuditEvent[];
  page_digest: string;
}

type RuntimeFetch = (
  input: string,
  init?: Parameters<typeof globalThis.fetch>[1]
) => Promise<Response>;

type RuntimeSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions
) => ChildProcess;

export interface StartAccordLockRuntimeOptions {
  binDirectory: string;
  dataDirectory: string;
  logger: RuntimeLogger;
  readinessFetch?: RuntimeFetch;
  startupTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  controlRequestTimeoutMs?: number;
  onUnexpectedExit?: (exit: AccordLockRuntimeExit) => void;
  spawnProcess?: RuntimeSpawn;
  tokenFactory?: () => string;
  controlRequestIdFactory?: () => string;
  platform?: typeof process.platform;
  acceptDirtyDevelopmentMarker?: boolean;
  expectedBinarySha256?: string;
  terminalPrograms?: readonly AccordLockTerminalProgramBinding[];
  networkDomains?: readonly string[];
}

export interface ReadAccordLockHistoricalAuditOptions {
  binDirectory: string;
  dataDirectory: string;
  expectedTaskId: string;
  expectedSessionId: string;
  expectedRunId: string;
  offset: number;
  limit: number;
  snapshotRevision: number | null;
  logger: RuntimeLogger;
  shutdownTimeoutMs?: number;
  controlRequestTimeoutMs?: number;
  spawnProcess?: RuntimeSpawn;
  controlRequestIdFactory?: () => string;
  platform?: typeof process.platform;
  acceptDirtyDevelopmentMarker?: boolean;
  expectedBinarySha256?: string;
}

export interface AccordLockRuntimeLaunchSpec {
  command: string;
  args: readonly string[];
  options: SpawnOptions;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]): boolean => {
  const actual = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  return (
    actual.length === expectedKeys.length &&
    actual.every((key, index) => key === expectedKeys[index])
  );
};

const existingRegularFile = (filePath: string): boolean => {
  try {
    const stat = fs.lstatSync(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
};

const sha256File = (filePath: string): string =>
  createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const delay = (milliseconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

export const accordLockRuntimeBinaryName = (
  platform: typeof process.platform = process.platform
): string => (platform === 'win32' ? `${RUNTIME_COMPONENT}.exe` : RUNTIME_COMPONENT);

export const generateAccordLockRuntimeToken = (): string =>
  randomBytes(TOKEN_BYTES).toString('base64url');

export const buildGoosePolicyEnvironment = (
  runtimeUrl: string,
  token: string,
  governedNetwork = false
): Readonly<Record<string, string>> => {
  const environment: Record<string, string> = {
    [ACCORDLOCK_RUNTIME_URL_ENV]: runtimeUrl,
    [ACCORDLOCK_RUNTIME_TOKEN_ENV]: token,
  };
  if (governedNetwork) environment[ACCORDLOCK_GOVERNED_NETWORK_ENV] = '1';
  return Object.freeze(environment);
};

export const validateAccordLockRuntimeBuildMarker = (
  value: unknown,
  expectedBinary: string,
  acceptDirtyDevelopmentMarker = false
): AccordLockRuntimeBuildMarker => {
  if (!isRecord(value)) {
    throw new Error('AccordLock runtime build marker must be a JSON object');
  }

  const expectedKeys = [
    'binary',
    'binary_sha256',
    'component',
    'distribution',
    'protocol_version',
    'schema_version',
    'source_commit',
    'source_dirty',
  ].sort();
  if (!hasExactKeys(value, expectedKeys)) {
    throw new Error('AccordLock runtime build marker fields are missing or unexpected');
  }

  if (
    value.schema_version !== RUNTIME_BUILD_MARKER_SCHEMA_VERSION ||
    value.distribution !== RUNTIME_DISTRIBUTION ||
    value.component !== RUNTIME_COMPONENT ||
    value.protocol_version !== RUNTIME_PROTOCOL_VERSION
  ) {
    throw new Error('AccordLock runtime build marker identifies an incompatible component');
  }
  if (typeof value.source_dirty !== 'boolean') {
    throw new Error('AccordLock runtime source dirty state is malformed');
  }
  if (value.source_dirty && !acceptDirtyDevelopmentMarker) {
    throw new Error('AccordLock runtime must be built from a clean source tree');
  }
  if (typeof value.source_commit !== 'string' || !/^[0-9a-f]{40}$/.test(value.source_commit)) {
    throw new Error('AccordLock runtime source commit is missing or malformed');
  }
  if (
    value.source_commit === '0'.repeat(40) &&
    !(value.source_dirty && acceptDirtyDevelopmentMarker)
  ) {
    throw new Error(
      'AccordLock zero source commit sentinel is allowed only for an explicitly dirty development build'
    );
  }
  if (value.binary !== expectedBinary) {
    throw new Error(`AccordLock runtime marker must declare ${expectedBinary}`);
  }
  if (typeof value.binary_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.binary_sha256)) {
    throw new Error('AccordLock runtime digest is missing or malformed');
  }

  return value as unknown as AccordLockRuntimeBuildMarker;
};

export const resolveAccordLockRuntimeBundle = (
  binDirectory: string,
  platform: typeof process.platform = process.platform,
  acceptDirtyDevelopmentMarker = false,
  expectedBinarySha256?: string
): AccordLockRuntimeBundle => {
  const expectedBinary = accordLockRuntimeBinaryName(platform);
  const resolvedBinDirectory = path.resolve(binDirectory);
  const markerPath = path.join(resolvedBinDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME);
  const binaryPath = path.join(resolvedBinDirectory, expectedBinary);

  if (!existingRegularFile(markerPath)) {
    throw new Error(`Missing bundled AccordLock runtime marker: ${markerPath}`);
  }
  if (!existingRegularFile(binaryPath)) {
    throw new Error(`Missing bundled AccordLock runtime binary: ${binaryPath}`);
  }

  let markerJson: unknown;
  try {
    markerJson = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
  } catch (error) {
    throw new Error(`Invalid AccordLock runtime build marker: ${errorMessage(error)}`);
  }
  const marker = validateAccordLockRuntimeBuildMarker(
    markerJson,
    expectedBinary,
    acceptDirtyDevelopmentMarker
  );
  if (expectedBinarySha256 !== undefined) {
    if (!/^[0-9a-f]{64}$/u.test(expectedBinarySha256)) {
      throw new Error('Embedded AccordLock runtime digest is missing or malformed');
    }
    if (marker.binary_sha256 !== expectedBinarySha256) {
      throw new Error('AccordLock runtime marker does not match the embedded application digest');
    }
  }
  const actualDigest = sha256File(binaryPath);
  if (actualDigest !== marker.binary_sha256) {
    throw new Error(`AccordLock runtime digest mismatch for ${expectedBinary}`);
  }

  return { binaryPath, markerPath, marker };
};

export const buildAccordLockRuntimeLaunchSpec = (
  bundle: AccordLockRuntimeBundle,
  token: string,
  dataDirectory: string,
  baseEnvironment: Readonly<Record<string, string | undefined>> = process.env,
  terminalPrograms: readonly AccordLockTerminalProgramBinding[] = [],
  networkDomains: readonly string[] = []
): AccordLockRuntimeLaunchSpec => {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error('AccordLock runtime launch token must contain 256 bits encoded as base64url');
  }

  const environment: Record<string, string | undefined> = {};
  for (const key of RUNTIME_OS_ENV_ALLOWLIST) {
    if (baseEnvironment[key] !== undefined) {
      environment[key] = baseEnvironment[key];
    }
  }
  environment[ACCORDLOCK_RUNTIME_TOKEN_ENV] = token;
  environment.ACCORDLOCK_RUNTIME_DATA_DIR = path.resolve(dataDirectory);

  const args = ['serve', '--host', '127.0.0.1', '--port', '0', '--ready-line', '--control-stdio'];
  let previousAlias = '';
  for (const program of [...terminalPrograms].sort((left, right) =>
    left.alias.localeCompare(right.alias, 'en-US')
  )) {
    if (
      !/^[a-z0-9_-]{1,64}$/u.test(program.alias) ||
      program.alias <= previousAlias ||
      !/^sha256:[0-9a-f]{64}$/u.test(program.executable_sha256) ||
      !path.isAbsolute(program.executable_path)
    ) {
      throw new Error('AccordLock terminal program launch binding is malformed or duplicated');
    }
    previousAlias = program.alias;
    args.push(
      '--terminal-program',
      `${program.alias}=${program.executable_sha256}=${program.executable_path}`
    );
  }
  let previousDomain = '';
  for (const domain of [...networkDomains].sort((left, right) =>
    left.localeCompare(right, 'en-US')
  )) {
    if (
      domain <= previousDomain ||
      domain.length > 253 ||
      domain !== domain.toLowerCase() ||
      !domain.includes('.') ||
      domain.endsWith('.') ||
      domain === 'localhost' ||
      domain.endsWith('.localhost') ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(domain) ||
      domain.includes(':') ||
      domain
        .split('.')
        .some(
          (label) =>
            label.length === 0 ||
            label.length > 63 ||
            label.startsWith('-') ||
            label.endsWith('-') ||
            !/^[a-z0-9-]+$/u.test(label)
        )
    ) {
      throw new Error('AccordLock network access policy is malformed or duplicated');
    }
    previousDomain = domain;
    args.push('--https-domain', domain);
  }

  return {
    command: bundle.binaryPath,
    args,
    options: {
      cwd: path.dirname(bundle.binaryPath),
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  };
};

export const buildAccordLockHistoricalAuditLaunchSpec = (
  bundle: AccordLockRuntimeBundle,
  dataDirectory: string,
  baseEnvironment: Readonly<Record<string, string | undefined>> = process.env
): AccordLockRuntimeLaunchSpec => {
  if (!path.isAbsolute(dataDirectory)) {
    throw new Error('Historical AccordLock ledger directory must be absolute');
  }
  const environment: Record<string, string | undefined> = {};
  for (const key of RUNTIME_OS_ENV_ALLOWLIST) {
    if (baseEnvironment[key] !== undefined) environment[key] = baseEnvironment[key];
  }
  environment.ACCORDLOCK_RUNTIME_DATA_DIR = dataDirectory;
  return {
    command: bundle.binaryPath,
    args: ['audit', '--control-stdio'],
    options: {
      cwd: path.dirname(bundle.binaryPath),
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  };
};

export const parseAccordLockRuntimeReadyLine = (line: string): string | null => {
  if (!line.startsWith(ACCORDLOCK_RUNTIME_READY_PREFIX)) {
    return null;
  }
  if (Buffer.byteLength(line, 'utf8') > MAX_READY_LINE_BYTES) {
    throw new Error('AccordLock runtime ready line is too large');
  }

  let payload: unknown;
  try {
    payload = JSON.parse(line.slice(ACCORDLOCK_RUNTIME_READY_PREFIX.length));
  } catch {
    throw new Error('AccordLock runtime emitted a malformed ready line');
  }
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, ['schema_version', 'url']) ||
    payload.schema_version !== RUNTIME_PROTOCOL_VERSION ||
    typeof payload.url !== 'string'
  ) {
    throw new Error('AccordLock runtime emitted an incompatible ready line');
  }

  let url: URL;
  try {
    url = new URL(payload.url);
  } catch {
    throw new Error('AccordLock runtime emitted an invalid URL');
  }
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    !url.port ||
    url.pathname !== '/' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('AccordLock runtime must bind an ephemeral IPv4 loopback HTTP endpoint');
  }

  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('AccordLock runtime emitted an invalid loopback port');
  }
  return url.origin;
};

const validateHealthResponse = async (response: Response): Promise<boolean> => {
  if (!response.ok || response.status !== 200) {
    return false;
  }
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_HEALTH_RESPONSE_BYTES) {
    return false;
  }
  try {
    const payload: unknown = JSON.parse(text);
    return (
      isRecord(payload) &&
      hasExactKeys(payload, ['schema_version', 'status']) &&
      payload.schema_version === RUNTIME_PROTOCOL_VERSION &&
      payload.status === 'READY'
    );
  } catch {
    return false;
  }
};

const probeRuntimeHealth = async (
  runtimeUrl: string,
  token: string,
  readinessFetch: RuntimeFetch
): Promise<boolean> => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1_000);
  try {
    const response = await readinessFetch(`${runtimeUrl}${RUNTIME_HEALTH_PATH}`, {
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      headers: {
        Authorization: `Bearer ${token}`,
        'Cache-Control': 'no-store',
      },
      signal: controller.signal,
    });
    return await validateHealthResponse(response);
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
};

const readBoundedRuntimeResponse = async (
  response: Response,
  maximumBytes: number
): Promise<Uint8Array> => {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel('AccordLock runtime response exceeds the bounded profile');
        throw new Error('AccordLock runtime response exceeds the bounded profile');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new Uint8Array(
    Buffer.concat(
      chunks.map((chunk) => Buffer.from(chunk)),
      length
    )
  );
};

const forwardRuntimeRequest = async (
  runtimeUrl: string,
  token: string,
  requestFetch: RuntimeFetch,
  requestPath: AccordLockRuntimePath,
  method: AccordLockRuntimeMethod,
  body: Uint8Array
): Promise<AccordLockApprovalProxyResponse> => {
  const isHealth = requestPath === RUNTIME_HEALTH_PATH;
  const requestTimeoutMs =
    requestPath === TERMINAL_EXECUTION_PATH
      ? TERMINAL_EXECUTION_REQUEST_TIMEOUT_MS
      : requestPath === NETWORK_EXECUTION_PATH
        ? NETWORK_EXECUTION_REQUEST_TIMEOUT_MS
        : DEFAULT_CONTROL_REQUEST_TIMEOUT_MS;
  const requestLimit = accordLockApprovalProxyRequestLimit(requestPath);
  const responseLimit = accordLockApprovalProxyResponseLimit(requestPath);
  if ((isHealth && method !== 'GET') || (!isHealth && method !== 'POST')) {
    throw new Error('AccordLock runtime proxy route and method do not match');
  }
  if (
    !ArrayBuffer.isView(body) ||
    body.byteLength > requestLimit ||
    (isHealth && body.byteLength !== 0)
  ) {
    throw new Error('AccordLock runtime proxy body is outside the bounded profile');
  }
  const response = await requestFetch(`${runtimeUrl}${requestPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(isHealth ? {} : { 'Content-Type': 'application/json' }),
    },
    body: isHealth ? undefined : Buffer.from(body),
    cache: 'no-store',
    redirect: 'error',
    signal: globalThis.AbortSignal.timeout(requestTimeoutMs),
  });
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    (!/^(0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > responseLimit)
  ) {
    throw new Error('AccordLock runtime response exceeds the bounded profile');
  }
  const responseBody = await readBoundedRuntimeResponse(response, responseLimit);
  return {
    status: response.status,
    contentType: response.headers.get('content-type'),
    body: responseBody,
  };
};

const CONTROL_MAGIC_BYTES = Buffer.from(ACCORDLOCK_CONTROL_FRAME_MAGIC, 'ascii');
const CONTROL_HEADER_BYTES = 8;
const CONTROL_TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const ZERO_SHA256_DIGEST = `sha256:${'0'.repeat(64)}`;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const MAX_AUDIT_PAGE_EVENTS = 100;
const MAX_AUDIT_OFFSET = 100_000;
const CONTROL_REQUEST_ERROR_CODES = new Set([
  'APPROVAL_CONFLICT',
  'INVALID_APPROVAL',
  'LEDGER_UNAVAILABLE',
  'UNSUPPORTED_METHOD',
  'UNSUPPORTED_SCHEMA',
]);
const REVOCATION_REQUEST_ERROR_CODES = new Set([
  'INVALID_REVOCATION_TIME',
  'INVALID_REVOCATION',
  'LEDGER_UNAVAILABLE',
  'MALFORMED_REQUEST',
  'REVOCATION_BINDING_MISMATCH',
  'REVOCATION_CONFLICT',
  'UNKNOWN_SESSION',
]);
const ACTION_APPROVAL_REQUEST_ERROR_CODES = new Set([
  'INVALID_ACTION_APPROVAL',
  'LEDGER_UNAVAILABLE',
  'MALFORMED_REQUEST',
  'ACTION_APPROVAL_SCOPE_MISMATCH',
  'ACTION_APPROVAL_CONFLICT',
  'UNKNOWN_SESSION',
]);
const FILE_RESTORE_REQUEST_ERROR_CODES = new Set([
  'FILE_RESTORE_CHALLENGE_MISMATCH',
  'FILE_RESTORE_INTEGRITY_MISMATCH',
  'FILE_RESTORE_STATE_CORRUPT',
  'FILE_RESTORE_STATE_STALE',
  'FILE_RESTORE_UNAVAILABLE',
  'FILE_RESTORE_UNSAFE_PATH',
  'INVALID_FILE_RESTORE_EVIDENCE',
  'INVALID_FILE_RESTORE_REQUEST',
  'UNKNOWN_FILE_RECOVERY',
]);
const AUDIT_REQUEST_ERROR_CODES = new Set([
  'AUDIT_HISTORY_TOO_LARGE',
  'AUDIT_PAGE_TOO_LARGE',
  'AUDIT_SNAPSHOT_CHANGED',
  'AUDIT_STATE_CORRUPT',
  'INVALID_AUDIT_QUERY',
  'LEDGER_UNAVAILABLE',
  'MALFORMED_REQUEST',
  'UNKNOWN_SESSION',
]);
const CONTROL_FATAL_ERROR_CODES = new Set([
  'FRAME_HEADER_INVALID',
  'FRAME_TOO_LARGE',
  'FRAME_TRUNCATED',
  'INVALID_REQUEST_ID',
  'MALFORMED_REQUEST',
]);

interface ApprovalControlResponse {
  schema_version: 2;
  request_id: string | null;
  status: 'ACK' | 'ERROR';
  code: string;
  approval_digest: string | null;
}

interface RevocationControlResponse {
  schema_version: 2;
  request_id: string | null;
  status: 'ACK' | 'ERROR';
  code: string;
  revocation_digest: string | null;
  task_id: string | null;
  session_id: string | null;
  run_id: string | null;
}

interface ActionApprovalControlResponse {
  schema_version: 2;
  request_id: string | null;
  status: 'ACK' | 'ERROR';
  code: string;
  approval_digest: string | null;
  approval_id: string | null;
  proposal_digest: string | null;
  approval_request_hash: string | null;
}

interface FileRestoreControlResponse {
  schema_version: 2;
  request_id: string | null;
  status: 'ACK' | 'ERROR';
  code: string;
  challenge_hash: string | null;
  challenge: AccordLockFileRestoreChallenge | null;
  record_hash: string | null;
  record: AccordLockFileRestoreResult | null;
}

interface AuditControlResponse {
  schema_version: 2;
  request_id: string | null;
  status: 'ACK' | 'ERROR';
  code: string;
  page: AccordLockSessionAuditPage | null;
}

type ControlResponse =
  | ApprovalControlResponse
  | RevocationControlResponse
  | ActionApprovalControlResponse
  | FileRestoreControlResponse
  | AuditControlResponse;

interface PendingApproval {
  kind: 'approval';
  requestId: string;
  expectedApprovalDigest: string;
  resolve: (record: AccordLockAuthorizationRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingRevocation {
  kind: 'revocation';
  requestId: string;
  expectedRevocationDigest: string;
  revocation: SessionRevocation;
  resolve: (record: AccordLockRevocationRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingActionApproval {
  kind: 'action-approval';
  requestId: string;
  expectedApprovalDigest: string;
  actionApproval: AccordLockActionApproval;
  resolve: (record: AccordLockActionApprovalRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingFileRestorePrepare {
  kind: 'file-restore-prepare';
  requestId: string;
  recoveryId: string;
  resolve: (record: AccordLockFileRestorePreparation | AccordLockFileRestoreRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingFileRestoreCommit {
  kind: 'file-restore-commit';
  requestId: string;
  challenge: AccordLockFileRestoreChallenge;
  challengeHash: string;
  resolve: (record: AccordLockFileRestoreRecord) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingAudit {
  kind: 'audit';
  requestId: string;
  sessionId: string;
  offset: number;
  limit: number;
  snapshotRevision: number | null;
  resolve: (page: AccordLockSessionAuditPage) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

type PendingControlRequest =
  | PendingApproval
  | PendingRevocation
  | PendingActionApproval
  | PendingFileRestorePrepare
  | PendingFileRestoreCommit
  | PendingAudit;

const canonicalUuid = (value: unknown): value is string =>
  typeof value === 'string' && CANONICAL_UUID.test(value) && value !== NIL_UUID;

const containsControlCharacter = (value: string): boolean =>
  Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
  });

const boundedText = (value: unknown, maximumBytes: number): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.trim() === value &&
  Buffer.byteLength(value, 'utf8') <= maximumBytes &&
  !containsControlCharacter(value);

const compareUtf8 = (left: string, right: string): number =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

const canonicalControlJson = (value: unknown): string => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalControlJson).join(',')}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalControlJson(value[key])}`)
      .join(',')}}`;
  }
  throw new Error('AccordLock control payload contains non-canonical JSON');
};

const controlPayloadDigest = (value: unknown): string =>
  `sha256:${createHash('sha256').update(canonicalControlJson(value), 'utf8').digest('hex')}`;

const domainSeparatedControlPayloadDigest = (domain: Buffer, value: unknown): string =>
  `sha256:${createHash('sha256')
    .update(domain)
    .update(canonicalControlJson(value), 'utf8')
    .digest('hex')}`;

/**
 * Stable v2 restore challenge digest shared with the trusted Rust runtime.
 * Preimage: ASCII domain including its trailing NUL, then canonical JSON UTF-8.
 */
export const accordLockFileRestoreChallengeDigest = (
  challenge: AccordLockFileRestoreChallenge
): string => domainSeparatedControlPayloadDigest(FILE_RESTORE_CHALLENGE_DIGEST_DOMAIN, challenge);

/**
 * Stable v2 restore record digest shared with the trusted Rust runtime.
 * Preimage: ASCII domain including its trailing NUL, then canonical JSON UTF-8.
 */
export const accordLockFileRestoreRecordDigest = (record: AccordLockFileRestoreResult): string =>
  domainSeparatedControlPayloadDigest(FILE_RESTORE_RECORD_DIGEST_DOMAIN, record);

/**
 * Stable v6 audit-page digest shared with the trusted Rust runtime.
 * The snapshot revision prevents pages from different ledger states being
 * combined into one export.
 */
export const accordLockSessionAuditPageDigest = (
  page: Omit<AccordLockSessionAuditPage, 'page_digest' | 'events'> & {
    readonly events: readonly AccordLockSessionAuditEvent[];
  }
): string =>
  domainSeparatedControlPayloadDigest(SESSION_AUDIT_PAGE_DIGEST_DOMAIN, [
    page.schema_version,
    page.task_id,
    page.session_id,
    page.run_id,
    page.offset,
    page.next_offset,
    page.total_events,
    page.snapshot_revision,
    page.snapshot_at,
    page.events,
  ]);

const validateTaskPolicyShape = (value: AccordLockTaskPolicy): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'preauthorized_capabilities',
      'task_objective_hash',
      'protected_paths',
      'schema_version',
    ]) ||
    value.schema_version !== TASK_POLICY_SCHEMA_VERSION ||
    typeof value.task_objective_hash !== 'string' ||
    !SHA256_DIGEST.test(value.task_objective_hash) ||
    value.task_objective_hash === ZERO_SHA256_DIGEST ||
    !Array.isArray(value.preauthorized_capabilities) ||
    value.preauthorized_capabilities.length > MAX_AUTOMATIC_CAPABILITIES ||
    !Array.isArray(value.protected_paths) ||
    value.protected_paths.length > MAX_PROTECTED_PATHS
  ) {
    throw new Error('AccordLock task policy is outside the strict control profile');
  }

  let previous: AccordLockCapability | undefined;
  for (const capability of value.preauthorized_capabilities) {
    if (
      !isRecord(capability) ||
      !hasExactKeys(capability, ['extension_id', 'tool_name']) ||
      capability.extension_id !== 'developer' ||
      (capability.tool_name !== 'read' && capability.tool_name !== 'tree')
    ) {
      throw new Error('AccordLock automatic capability is outside the native safe profile');
    }
    if (
      previous &&
      (compareUtf8(previous.extension_id, capability.extension_id) > 0 ||
        (previous.extension_id === capability.extension_id &&
          compareUtf8(previous.tool_name, capability.tool_name) >= 0))
    ) {
      throw new Error('AccordLock automatic capabilities must be sorted and unique');
    }
    previous = capability;
  }

  let previousPath: string | undefined;
  for (const protectedPath of value.protected_paths) {
    if (
      !boundedText(protectedPath, MAX_REVIEW_RELATIVE_PATH_BYTES) ||
      !Array.from(protectedPath).every((character) => (character.codePointAt(0) ?? 128) <= 0x7f) ||
      protectedPath !== protectedPath.toLowerCase() ||
      protectedPath.startsWith('/') ||
      protectedPath.endsWith('/') ||
      protectedPath.includes('\\') ||
      protectedPath.includes(':') ||
      protectedPath
        .split('/')
        .some((component) => component.length === 0 || component === '.' || component === '..') ||
      (previousPath !== undefined && compareUtf8(previousPath, protectedPath) >= 0)
    ) {
      throw new Error('AccordLock protected paths must be safe, sorted, and unique');
    }
    previousPath = protectedPath;
  }
};

export const accordLockObjectiveDigest = (objective: string): string =>
  `sha256:${createHash('sha256').update(objective, 'utf8').digest('hex')}`;

export const accordLockTaskPolicyDigest = (taskPolicy: AccordLockTaskPolicy): string => {
  validateTaskPolicyShape(taskPolicy);
  const canonical = Buffer.from(canonicalControlJson(taskPolicy), 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(canonical.length));
  return `sha256:${createHash('sha256')
    .update(TASK_POLICY_DIGEST_DOMAIN, 'ascii')
    .update(Buffer.from([0]))
    .update(length)
    .update(canonical)
    .digest('hex')}`;
};

const approvedSessionDigest = (approvedSession: ApprovedSession): string =>
  controlPayloadDigest(approvedSession);

const sessionRevocationDigest = (revocation: SessionRevocation): string =>
  controlPayloadDigest(revocation);

const actionApprovalDigest = (approval: AccordLockActionApproval): string =>
  controlPayloadDigest(approval);

const validateApprovedSession = (value: ApprovedSession): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'approved_at',
      'capabilities',
      'expires_at',
      'task_id',
      'policy_epoch',
      'run_id',
      'schema_version',
      'task_policy',
      'task_policy_hash',
      'session_id',
      'task_objective',
      'workspace_root',
    ]) ||
    value.schema_version !== APPROVED_SESSION_SCHEMA_VERSION ||
    !canonicalUuid(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256) ||
    !boundedText(value.workspace_root, 4_096) ||
    !boundedText(value.task_objective, 16_384) ||
    !Number.isSafeInteger(value.policy_epoch) ||
    value.policy_epoch <= 0 ||
    !isRecord(value.task_policy) ||
    typeof value.task_policy_hash !== 'string' ||
    !SHA256_DIGEST.test(value.task_policy_hash) ||
    !Number.isSafeInteger(value.approved_at) ||
    value.approved_at < 0 ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at <= value.approved_at ||
    value.expires_at - value.approved_at > MAX_APPROVAL_LIFETIME_SECONDS ||
    !Array.isArray(value.capabilities) ||
    value.capabilities.length < 1 ||
    value.capabilities.length > MAX_CAPABILITIES
  ) {
    throw new Error('AccordLock approved session is outside the strict control profile');
  }

  validateTaskPolicyShape(value.task_policy);
  if (accordLockObjectiveDigest(value.task_objective) !== value.task_policy.task_objective_hash) {
    throw new Error('AccordLock task objective does not match the approved policy');
  }
  if (accordLockTaskPolicyDigest(value.task_policy) !== value.task_policy_hash) {
    throw new Error('AccordLock task policy hash does not match the approved policy');
  }

  let previous: AccordLockCapability | undefined;
  for (const capability of value.capabilities) {
    if (
      !isRecord(capability) ||
      !hasExactKeys(capability, ['extension_id', 'tool_name']) ||
      !boundedText(capability.extension_id, 256) ||
      !boundedText(capability.tool_name, 256)
    ) {
      throw new Error('AccordLock approved capability is outside the strict control profile');
    }
    if (
      previous &&
      (compareUtf8(previous.extension_id, capability.extension_id) > 0 ||
        (previous.extension_id === capability.extension_id &&
          compareUtf8(previous.tool_name, capability.tool_name) >= 0))
    ) {
      throw new Error('AccordLock approved capabilities must be sorted and unique');
    }
    previous = {
      extension_id: capability.extension_id,
      tool_name: capability.tool_name,
    };
  }
};

const validateSessionRevocation = (value: SessionRevocation): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['run_id', 'schema_version', 'session_id', 'task_id']) ||
    value.schema_version !== RUNTIME_PROTOCOL_VERSION ||
    !canonicalUuid(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256)
  ) {
    throw new Error('AccordLock session revocation is outside the strict control profile');
  }
};

const validateActionApproval = (value: AccordLockActionApproval): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'expires_at',
      'decision',
      'prestate_hash',
      'proposal_digest',
      'policy_decision',
      'policy_decision_hash',
      'approval_request_hash',
      'approval_evidence_hash',
      'approval_id',
      'decided_at',
      'run_id',
      'schema_version',
      'task_policy_hash',
      'task_requirement',
      'session_id',
      'tool_call_id',
      'transformation_step',
      'task_id',
    ]) ||
    value.schema_version !== 2 ||
    !canonicalUuid(value.approval_id) ||
    !canonicalUuid(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256) ||
    !boundedText(value.tool_call_id, 256) ||
    !SHA256_DIGEST.test(value.proposal_digest) ||
    value.proposal_digest === ZERO_SHA256_DIGEST ||
    !SHA256_DIGEST.test(value.task_policy_hash) ||
    value.task_policy_hash === ZERO_SHA256_DIGEST ||
    !SHA256_DIGEST.test(value.prestate_hash) ||
    value.prestate_hash === ZERO_SHA256_DIGEST ||
    !SHA256_DIGEST.test(value.approval_request_hash) ||
    value.approval_request_hash === ZERO_SHA256_DIGEST ||
    !isRecord(value.task_requirement) ||
    !isRecord(value.transformation_step) ||
    !isRecord(value.policy_decision) ||
    !SHA256_DIGEST.test(value.policy_decision_hash) ||
    value.policy_decision_hash === ZERO_SHA256_DIGEST ||
    (value.decision !== 'APPROVED' && value.decision !== 'DENIED') ||
    !SHA256_DIGEST.test(value.approval_evidence_hash) ||
    value.approval_evidence_hash === ZERO_SHA256_DIGEST ||
    !Number.isSafeInteger(value.decided_at) ||
    value.decided_at < 0 ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at <= value.decided_at ||
    value.expires_at - value.decided_at > MAX_ACTION_APPROVAL_LIFETIME_SECONDS
  ) {
    throw new Error('AccordLock action approval is outside the strict control profile');
  }
};

const safeRestoreRelativePath = (value: unknown): value is string =>
  boundedText(value, MAX_REVIEW_RELATIVE_PATH_BYTES) &&
  !value.startsWith('/') &&
  !value.startsWith('\\') &&
  !value.includes('\\') &&
  !value.includes(':') &&
  value
    .split('/')
    .every((component) => component.length > 0 && component !== '.' && component !== '..');

const validateFileRestoreChallenge = (value: AccordLockFileRestoreChallenge): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'content_sha256',
      'original_bytes',
      'original_record_hash',
      'original_record_id',
      'prepared_at',
      'recovery_id',
      'relative_path',
      'restore_id',
      'run_id',
      'schema_version',
      'session_id',
      'task_id',
      'workspace_root',
    ]) ||
    value.schema_version !== RUNTIME_PROTOCOL_VERSION ||
    !canonicalUuid(value.restore_id) ||
    !canonicalUuid(value.recovery_id) ||
    !canonicalUuid(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256) ||
    !canonicalUuid(value.original_record_id) ||
    !SHA256_DIGEST.test(value.original_record_hash) ||
    value.original_record_hash === ZERO_SHA256_DIGEST ||
    !boundedText(value.workspace_root, 4_096) ||
    !safeRestoreRelativePath(value.relative_path) ||
    !SHA256_DIGEST.test(value.content_sha256) ||
    value.content_sha256 === ZERO_SHA256_DIGEST ||
    !Number.isSafeInteger(value.original_bytes) ||
    value.original_bytes < 0 ||
    !Number.isSafeInteger(value.prepared_at) ||
    value.prepared_at < 0
  ) {
    throw new Error('AccordLock file restore challenge is outside the strict control profile');
  }
};

const validateFileRestoreResult = (value: AccordLockFileRestoreResult): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'challenge_hash',
      'completed_at',
      'content_sha256',
      'original_bytes',
      'original_record_hash',
      'original_record_id',
      'recovery_id',
      'relative_path',
      'restore_id',
      'run_id',
      'schema_version',
      'session_id',
      'task_id',
      'workspace_root',
    ]) ||
    value.schema_version !== RUNTIME_PROTOCOL_VERSION ||
    !canonicalUuid(value.restore_id) ||
    !canonicalUuid(value.recovery_id) ||
    !SHA256_DIGEST.test(value.challenge_hash) ||
    value.challenge_hash === ZERO_SHA256_DIGEST ||
    !canonicalUuid(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256) ||
    !canonicalUuid(value.original_record_id) ||
    !SHA256_DIGEST.test(value.original_record_hash) ||
    value.original_record_hash === ZERO_SHA256_DIGEST ||
    !boundedText(value.workspace_root, 4_096) ||
    !safeRestoreRelativePath(value.relative_path) ||
    !SHA256_DIGEST.test(value.content_sha256) ||
    value.content_sha256 === ZERO_SHA256_DIGEST ||
    !Number.isSafeInteger(value.original_bytes) ||
    value.original_bytes < 0 ||
    !Number.isSafeInteger(value.completed_at) ||
    value.completed_at < 0
  ) {
    throw new Error('AccordLock file restore record is outside the strict control profile');
  }
};

const INTENT_FINDING_REASON_ORDER: readonly AccordLockIntentFindingReason[] = [
  'SUPPORTED',
  'MISSING_EVIDENCE',
  'INCONCLUSIVE_EVIDENCE',
  'UNVERIFIED_PROVENANCE',
  'EXPIRED_CALIBRATION',
  'CONFIDENCE_THRESHOLD_UNCERTAIN',
  'BELOW_THRESHOLD',
  'CONTRADICTORY_EVIDENCE',
  'SCOPE_MISMATCH',
  'EVIDENCE_CHAIN_MISMATCH',
  'LEDGER_SNAPSHOT_MISMATCH',
  'TRUST_POLICY_MISMATCH',
];

const REVIEW_FINDINGS = new Set<AccordLockIntentFindingReason>([
  'MISSING_EVIDENCE',
  'INCONCLUSIVE_EVIDENCE',
  'UNVERIFIED_PROVENANCE',
  'EXPIRED_CALIBRATION',
  'CONFIDENCE_THRESHOLD_UNCERTAIN',
]);

const BLOCKING_FINDINGS = new Set<AccordLockIntentFindingReason>([
  'BELOW_THRESHOLD',
  'CONTRADICTORY_EVIDENCE',
  'SCOPE_MISMATCH',
  'EVIDENCE_CHAIN_MISMATCH',
  'LEDGER_SNAPSHOT_MISMATCH',
  'TRUST_POLICY_MISMATCH',
]);

const validateIntentAssessment = (
  value: AccordLockIntentAssessment,
  expectedProfile: AccordLockIntentAssessment['profile']
): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'evidence_count',
      'finding_reasons',
      'profile',
      'schema_version',
      'status',
    ]) ||
    value.schema_version !== 1 ||
    value.profile !== expectedProfile ||
    !['VERIFIED', 'REVIEW_REQUIRED', 'BLOCKED'].includes(value.status) ||
    !Number.isSafeInteger(value.evidence_count) ||
    value.evidence_count < 0 ||
    value.evidence_count > 65_535 ||
    !Array.isArray(value.finding_reasons) ||
    value.finding_reasons.length > INTENT_FINDING_REASON_ORDER.length ||
    value.finding_reasons.some((reason, index, reasons) => {
      const rank = INTENT_FINDING_REASON_ORDER.indexOf(reason);
      const previousRank =
        index === 0 ? -1 : INTENT_FINDING_REASON_ORDER.indexOf(reasons[index - 1]);
      return rank < 0 || rank <= previousRank;
    })
  ) {
    throw new Error('AccordLock intent assessment is outside the strict control profile');
  }

  const verified =
    value.status === 'VERIFIED' &&
    value.evidence_count > 0 &&
    value.finding_reasons.length > 0 &&
    value.finding_reasons.every((reason) => reason === 'SUPPORTED');
  const review =
    value.status === 'REVIEW_REQUIRED' &&
    value.finding_reasons.some((reason) => REVIEW_FINDINGS.has(reason));
  const blocked =
    value.status === 'BLOCKED' &&
    value.finding_reasons.some((reason) => BLOCKING_FINDINGS.has(reason));
  if (!verified && !review && !blocked) {
    throw new Error('AccordLock intent assessment status is inconsistent with its findings');
  }
};

const intentAssessmentIsValid = (
  value: AccordLockIntentAssessment,
  expectedProfile: AccordLockIntentAssessment['profile']
): boolean => {
  try {
    validateIntentAssessment(value, expectedProfile);
    return true;
  } catch {
    return false;
  }
};

const validateAuditEvent = (value: AccordLockSessionAuditEvent): void => {
  if (
    !isRecord(value) ||
    !boundedText(value.type, 64) ||
    !boundedText(value.event_id, 512) ||
    !Number.isSafeInteger(value.recorded_at) ||
    value.recorded_at < 0
  ) {
    throw new Error('AccordLock audit event is outside the strict control profile');
  }
  const digest = (candidate: unknown): candidate is string =>
    typeof candidate === 'string' &&
    SHA256_DIGEST.test(candidate) &&
    candidate !== ZERO_SHA256_DIGEST;
  const text = (candidate: unknown, maximum = 256): candidate is string =>
    boundedText(candidate, maximum);

  switch (value.type) {
    case 'SESSION_APPROVED':
      if (
        !hasExactKeys(value, [
          'event_id',
          'expires_at',
          'policy_hash',
          'recorded_at',
          'run_id',
          'task_id',
          'type',
          'workspace_root',
        ]) ||
        !canonicalUuid(value.task_id) ||
        !text(value.run_id) ||
        !text(value.workspace_root, 4_096) ||
        !digest(value.policy_hash) ||
        !Number.isSafeInteger(value.expires_at) ||
        value.expires_at <= value.recorded_at
      ) {
        throw new Error('AccordLock session audit event is invalid');
      }
      return;
    case 'SESSION_REVOKED':
      if (
        !hasExactKeys(value, [
          'event_id',
          'recorded_at',
          'revocation_digest',
          'run_id',
          'task_id',
          'type',
        ]) ||
        !canonicalUuid(value.task_id) ||
        !text(value.run_id) ||
        !digest(value.revocation_digest)
      ) {
        throw new Error('AccordLock revocation audit event is invalid');
      }
      return;
    case 'ACTION_DECISION':
      if (
        !hasExactKeys(value, [
          'approval_id',
          'consumed',
          'decision',
          'event_id',
          'evidence_hash',
          'proposal_digest',
          'recorded_at',
          'tool_call_id',
          'type',
        ]) ||
        !canonicalUuid(value.approval_id) ||
        !text(value.tool_call_id) ||
        !digest(value.proposal_digest) ||
        (value.decision !== 'APPROVED' && value.decision !== 'DENIED') ||
        !digest(value.evidence_hash) ||
        typeof value.consumed !== 'boolean'
      ) {
        throw new Error('AccordLock action-decision audit event is invalid');
      }
      return;
    case 'ACTION_STARTED':
      if (
        !hasExactKeys(value, [
          'authorization_id',
          'conformance_evaluation_hashes',
          'decision_reason_code',
          'event_id',
          'extension_id',
          'intent_assessment',
          'intent_evaluation_hash',
          'proposal_digest',
          'recorded_at',
          'review_status',
          'request_hash',
          'task_control_hash',
          'task_control_provenance',
          'task_scope_status',
          'tool_call_id',
          'tool_name',
          'type',
        ]) ||
        !canonicalUuid(value.authorization_id) ||
        !text(value.tool_call_id) ||
        !text(value.extension_id) ||
        !text(value.tool_name) ||
        !digest(value.proposal_digest) ||
        !digest(value.request_hash) ||
        !digest(value.intent_evaluation_hash) ||
        !Array.isArray(value.conformance_evaluation_hashes) ||
        value.conformance_evaluation_hashes.length > 16 ||
        value.conformance_evaluation_hashes.some(
          (hash, index, hashes) =>
            !digest(hash) || (index > 0 && compareUtf8(hashes[index - 1], hash) >= 0)
        ) ||
        !digest(value.task_control_hash) ||
        !intentAssessmentIsValid(value.intent_assessment, 'PRE_EXECUTION') ||
        value.task_control_provenance !== 'DECISION_BOUND' ||
        !(
          (value.task_scope_status === 'WITHIN_APPROVED_ACCESS' &&
            value.review_status === 'NOT_REQUIRED' &&
            value.decision_reason_code === 'POLICY_CONFORMANT' &&
            value.conformance_evaluation_hashes.length > 0) ||
          (value.task_scope_status === 'REVIEW_REQUIRED' &&
            value.review_status === 'APPROVED' &&
            value.decision_reason_code === 'ACTION_APPROVAL_ACCEPTED' &&
            value.conformance_evaluation_hashes.length === 0)
        )
      ) {
        throw new Error('AccordLock action-start audit event is invalid');
      }
      return;
    case 'ACTION_COMPLETED':
      if (
        !hasExactKeys(value, [
          'authorization_id',
          'event_id',
          'decision_reason_code',
          'execution_lineage_hash',
          'intent_complete_assessment',
          'intent_complete_evaluation_hash',
          'intent_pre_assessment',
          'intent_pre_evaluation_hash',
          'outcome',
          'record_hash',
          'recorded_at',
          'review_status',
          'state',
          'task_control_hash',
          'task_control_provenance',
          'task_scope_status',
          'tool_call_id',
          'type',
        ]) ||
        !canonicalUuid(value.authorization_id) ||
        !text(value.tool_call_id) ||
        !text(value.outcome, 64) ||
        !['SUCCEEDED', 'EXECUTION_UNKNOWN'].includes(value.state) ||
        (value.record_hash !== null && !digest(value.record_hash)) ||
        !digest(value.execution_lineage_hash) ||
        !digest(value.intent_pre_evaluation_hash) ||
        (value.intent_complete_evaluation_hash !== null &&
          !digest(value.intent_complete_evaluation_hash)) ||
        !digest(value.task_control_hash) ||
        !intentAssessmentIsValid(value.intent_pre_assessment, 'PRE_EXECUTION') ||
        !intentAssessmentIsValid(value.intent_complete_assessment, 'COMPLETE_TRACE') ||
        !['LINEAGE_BOUND', 'EMBEDDED', 'RECONSTRUCTED'].includes(value.task_control_provenance) ||
        !(
          (value.task_scope_status === 'WITHIN_APPROVED_ACCESS' &&
            value.review_status === 'NOT_REQUIRED' &&
            value.decision_reason_code === 'POLICY_CONFORMANT') ||
          (value.task_scope_status === 'REVIEW_REQUIRED' &&
            value.review_status === 'APPROVED' &&
            value.decision_reason_code === 'ACTION_APPROVAL_ACCEPTED')
        )
      ) {
        throw new Error('AccordLock action-outcome audit event is invalid');
      }
      return;
    case 'ACTION_DENIED':
      if (
        !hasExactKeys(value, [
          'attempted_run_id',
          'denial_id',
          'event_id',
          'proposal_digest',
          'reason_code',
          'recorded_at',
          'tool_call_id',
          'type',
        ]) ||
        !Number.isSafeInteger(value.denial_id) ||
        value.denial_id <= 0 ||
        !text(value.attempted_run_id, 256) ||
        !text(value.tool_call_id) ||
        !digest(value.proposal_digest) ||
        !text(value.reason_code, 128)
      ) {
        throw new Error('AccordLock action-denial audit event is invalid');
      }
      return;
    case 'RESTORE_PREPARED':
      if (
        !hasExactKeys(value, [
          'content_hash',
          'event_id',
          'recorded_at',
          'recovery_id',
          'relative_path',
          'restore_id',
          'type',
        ]) ||
        !canonicalUuid(value.restore_id) ||
        !canonicalUuid(value.recovery_id) ||
        !safeRestoreRelativePath(value.relative_path) ||
        !digest(value.content_hash)
      ) {
        throw new Error('AccordLock restore-preparation audit event is invalid');
      }
      return;
    case 'RESTORE_COMPLETED':
      if (
        !hasExactKeys(value, [
          'event_id',
          'record_hash',
          'recorded_at',
          'recovery_id',
          'relative_path',
          'restore_id',
          'type',
        ]) ||
        !canonicalUuid(value.restore_id) ||
        !canonicalUuid(value.recovery_id) ||
        !safeRestoreRelativePath(value.relative_path) ||
        !digest(value.record_hash)
      ) {
        throw new Error('AccordLock restore-outcome audit event is invalid');
      }
      return;
    default:
      throw new Error('AccordLock audit event type is unsupported');
  }
};

const validateSessionAuditPage = (
  value: AccordLockSessionAuditPage,
  expectedSessionId: string,
  expectedOffset: number,
  expectedLimit: number,
  expectedSnapshotRevision: number | null
): void => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'events',
      'next_offset',
      'offset',
      'page_digest',
      'run_id',
      'schema_version',
      'session_id',
      'snapshot_at',
      'snapshot_revision',
      'task_id',
      'total_events',
    ]) ||
    value.schema_version !== SESSION_AUDIT_PAGE_SCHEMA_VERSION ||
    !canonicalUuid(value.task_id) ||
    value.session_id !== expectedSessionId ||
    !boundedText(value.run_id, 256) ||
    value.offset !== expectedOffset ||
    !Number.isSafeInteger(value.total_events) ||
    value.total_events < 1 ||
    !Number.isSafeInteger(value.snapshot_revision) ||
    value.snapshot_revision < 0 ||
    (expectedSnapshotRevision !== null && value.snapshot_revision !== expectedSnapshotRevision) ||
    !Number.isSafeInteger(value.snapshot_at) ||
    value.snapshot_at < 0 ||
    !Array.isArray(value.events) ||
    value.events.length > expectedLimit ||
    value.events.length > MAX_AUDIT_PAGE_EVENTS ||
    (value.next_offset !== null &&
      (!Number.isSafeInteger(value.next_offset) ||
        value.next_offset !== value.offset + value.events.length)) ||
    (value.next_offset === null && value.offset + value.events.length < value.total_events) ||
    typeof value.page_digest !== 'string' ||
    !SHA256_DIGEST.test(value.page_digest) ||
    value.page_digest === ZERO_SHA256_DIGEST
  ) {
    throw new Error('AccordLock audit page is outside the strict control profile');
  }

  const eventIds = new Set<string>();
  let previous: AccordLockSessionAuditEvent | undefined;
  for (const event of value.events) {
    validateAuditEvent(event);
    if (
      event.recorded_at > value.snapshot_at ||
      eventIds.has(event.event_id) ||
      (previous !== undefined &&
        (event.recorded_at > previous.recorded_at ||
          (event.recorded_at === previous.recorded_at &&
            compareUtf8(event.event_id, previous.event_id) > 0)))
    ) {
      throw new Error('AccordLock audit page ordering or identity is invalid');
    }
    if (
      (event.type === 'SESSION_APPROVED' || event.type === 'SESSION_REVOKED') &&
      (event.task_id !== value.task_id || event.run_id !== value.run_id)
    ) {
      throw new Error('AccordLock audit event does not match the page identity');
    }
    eventIds.add(event.event_id);
    previous = event;
  }

  const expectedDigest = accordLockSessionAuditPageDigest(value);
  if (value.page_digest !== expectedDigest) {
    throw new Error('AccordLock audit page digest does not match its content');
  }
};

const encodeControlFrame = (payload: unknown): Buffer => {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  if (body.length > ACCORDLOCK_CONTROL_MAX_FRAME_BYTES) {
    throw new Error('AccordLock control request exceeds the bounded frame profile');
  }
  const header = Buffer.alloc(CONTROL_HEADER_BYTES);
  CONTROL_MAGIC_BYTES.copy(header, 0);
  header.writeUInt32BE(body.length, CONTROL_MAGIC_BYTES.length);
  return Buffer.concat([header, body], header.length + body.length);
};

const parseControlResponse = (body: Buffer): ControlResponse => {
  let text: string;
  let payload: unknown;
  try {
    text = CONTROL_TEXT_DECODER.decode(body);
    payload = JSON.parse(text);
  } catch {
    throw new Error('AccordLock control channel emitted malformed UTF-8 JSON');
  }
  if (JSON.stringify(payload) !== text) {
    throw new Error('AccordLock control response is not in canonical JSON form');
  }
  if (!isRecord(payload)) {
    throw new Error('AccordLock control response violates the strict schema');
  }
  const commonIsValid =
    payload.schema_version === RUNTIME_PROTOCOL_VERSION &&
    (payload.request_id === null || canonicalUuid(payload.request_id)) &&
    (payload.status === 'ACK' || payload.status === 'ERROR') &&
    typeof payload.code === 'string';
  if (!commonIsValid) {
    throw new Error('AccordLock control response violates the strict schema');
  }

  if (
    hasExactKeys(payload, ['approval_digest', 'code', 'request_id', 'schema_version', 'status'])
  ) {
    if (
      payload.status === 'ACK' &&
      (payload.request_id === null ||
        (payload.code !== 'SESSION_APPROVED' && payload.code !== 'SESSION_ALREADY_APPROVED') ||
        typeof payload.approval_digest !== 'string' ||
        !SHA256_DIGEST.test(payload.approval_digest))
    ) {
      throw new Error('AccordLock approval acknowledgement is invalid');
    }
    if (
      payload.status === 'ERROR' &&
      (payload.approval_digest !== null ||
        (payload.request_id === null
          ? !CONTROL_FATAL_ERROR_CODES.has(payload.code as string)
          : !CONTROL_REQUEST_ERROR_CODES.has(payload.code as string)))
    ) {
      throw new Error('AccordLock control error response is invalid');
    }
    return payload as unknown as ApprovalControlResponse;
  }

  if (
    hasExactKeys(payload, [
      'code',
      'proposal_digest',
      'request_id',
      'approval_request_hash',
      'approval_digest',
      'approval_id',
      'schema_version',
      'status',
    ])
  ) {
    if (
      payload.status === 'ACK' &&
      (payload.request_id === null ||
        (payload.code !== 'ACTION_APPROVAL_REGISTERED' &&
          payload.code !== 'ACTION_APPROVAL_ALREADY_REGISTERED') ||
        typeof payload.approval_digest !== 'string' ||
        !SHA256_DIGEST.test(payload.approval_digest) ||
        !canonicalUuid(payload.approval_id) ||
        typeof payload.proposal_digest !== 'string' ||
        !SHA256_DIGEST.test(payload.proposal_digest) ||
        typeof payload.approval_request_hash !== 'string' ||
        !SHA256_DIGEST.test(payload.approval_request_hash))
    ) {
      throw new Error('AccordLock action approval acknowledgement is invalid');
    }
    if (
      payload.status === 'ERROR' &&
      (payload.request_id === null ||
        payload.approval_digest !== null ||
        payload.approval_id !== null ||
        payload.proposal_digest !== null ||
        payload.approval_request_hash !== null ||
        !ACTION_APPROVAL_REQUEST_ERROR_CODES.has(payload.code as string))
    ) {
      throw new Error('AccordLock action approval error response is invalid');
    }
    return payload as unknown as ActionApprovalControlResponse;
  }

  if (
    hasExactKeys(payload, [
      'challenge',
      'challenge_hash',
      'code',
      'record',
      'record_hash',
      'request_id',
      'schema_version',
      'status',
    ])
  ) {
    if (payload.status === 'ERROR') {
      if (
        payload.request_id === null ||
        payload.challenge_hash !== null ||
        payload.challenge !== null ||
        payload.record_hash !== null ||
        payload.record !== null ||
        !FILE_RESTORE_REQUEST_ERROR_CODES.has(payload.code as string)
      ) {
        throw new Error('AccordLock file restore error response is invalid');
      }
      return payload as unknown as FileRestoreControlResponse;
    }

    if (
      payload.request_id === null ||
      typeof payload.challenge_hash !== 'string' ||
      !SHA256_DIGEST.test(payload.challenge_hash) ||
      payload.challenge_hash === ZERO_SHA256_DIGEST
    ) {
      throw new Error('AccordLock file restore acknowledgement is invalid');
    }

    if (
      payload.code === 'FILE_RESTORE_PREPARED' ||
      payload.code === 'FILE_RESTORE_ALREADY_PREPARED'
    ) {
      if (!isRecord(payload.challenge) || payload.record_hash !== null || payload.record !== null) {
        throw new Error('AccordLock file restore preparation is invalid');
      }
      validateFileRestoreChallenge(payload.challenge as unknown as AccordLockFileRestoreChallenge);
      if (
        accordLockFileRestoreChallengeDigest(
          payload.challenge as unknown as AccordLockFileRestoreChallenge
        ) !== payload.challenge_hash
      ) {
        throw new Error('AccordLock file restore challenge hash does not match its content');
      }
      return payload as unknown as FileRestoreControlResponse;
    }

    if (
      payload.code !== 'FILE_RESTORE_COMMITTED' &&
      payload.code !== 'FILE_RESTORE_ALREADY_COMMITTED'
    ) {
      throw new Error('AccordLock file restore acknowledgement code is invalid');
    }
    if (
      payload.challenge !== null ||
      typeof payload.record_hash !== 'string' ||
      !SHA256_DIGEST.test(payload.record_hash) ||
      payload.record_hash === ZERO_SHA256_DIGEST ||
      !isRecord(payload.record)
    ) {
      throw new Error('AccordLock file restore record acknowledgement is invalid');
    }
    validateFileRestoreResult(payload.record as unknown as AccordLockFileRestoreResult);
    if (
      accordLockFileRestoreRecordDigest(
        payload.record as unknown as AccordLockFileRestoreResult
      ) !== payload.record_hash ||
      payload.record.challenge_hash !== payload.challenge_hash
    ) {
      throw new Error('AccordLock file restore record hash does not match its content');
    }
    return payload as unknown as FileRestoreControlResponse;
  }

  if (hasExactKeys(payload, ['code', 'page', 'request_id', 'schema_version', 'status'])) {
    if (
      payload.status === 'ACK' &&
      (payload.request_id === null ||
        payload.code !== 'SESSION_AUDIT_READY' ||
        !isRecord(payload.page))
    ) {
      throw new Error('AccordLock audit acknowledgement is invalid');
    }
    if (
      payload.status === 'ERROR' &&
      (payload.request_id === null ||
        payload.page !== null ||
        !AUDIT_REQUEST_ERROR_CODES.has(payload.code as string))
    ) {
      throw new Error('AccordLock audit error response is invalid');
    }
    return payload as unknown as AuditControlResponse;
  }

  if (
    !hasExactKeys(payload, [
      'code',
      'task_id',
      'request_id',
      'revocation_digest',
      'run_id',
      'schema_version',
      'session_id',
      'status',
    ])
  ) {
    throw new Error('AccordLock control response violates the strict schema');
  }
  if (
    payload.status === 'ACK' &&
    (payload.request_id === null ||
      (payload.code !== 'SESSION_REVOKED' && payload.code !== 'SESSION_ALREADY_REVOKED') ||
      typeof payload.revocation_digest !== 'string' ||
      !SHA256_DIGEST.test(payload.revocation_digest) ||
      !canonicalUuid(payload.task_id) ||
      !boundedText(payload.session_id, 256) ||
      !boundedText(payload.run_id, 256))
  ) {
    throw new Error('AccordLock revocation acknowledgement is invalid');
  }
  if (
    payload.status === 'ERROR' &&
    (payload.request_id === null ||
      payload.revocation_digest !== null ||
      payload.task_id !== null ||
      payload.session_id !== null ||
      payload.run_id !== null ||
      !REVOCATION_REQUEST_ERROR_CODES.has(payload.code as string))
  ) {
    throw new Error('AccordLock revocation error response is invalid');
  }
  return payload as unknown as RevocationControlResponse;
};

class AccordLockControlChannelClient {
  private buffer = Buffer.alloc(0);
  private pending: PendingControlRequest | null = null;
  private closedError: Error | null = null;

  constructor(
    private readonly input: Writable,
    private readonly requestTimeoutMs: number,
    private readonly requestIdFactory: () => string,
    private readonly onFatal: (error: Error) => void
  ) {}

  get isClosed(): boolean {
    return this.closedError !== null;
  }

  get failure(): Error | null {
    return this.closedError;
  }

  async authorizeTask(approvedSession: ApprovedSession): Promise<AccordLockAuthorizationRecord> {
    validateApprovedSession(approvedSession);
    if (this.closedError) {
      return Promise.reject(this.closedError);
    }
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'APPROVE_SESSION',
      approved_session: approvedSession,
    });
    const expectedApprovalDigest = approvedSessionDigest(approvedSession);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'approval',
        requestId,
        expectedApprovalDigest,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  async revokeSession(revocation: SessionRevocation): Promise<AccordLockRevocationRecord> {
    validateSessionRevocation(revocation);
    if (this.closedError) {
      return Promise.reject(this.closedError);
    }
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'REVOKE_SESSION',
      session_revocation: revocation,
    });
    const expectedRevocationDigest = sessionRevocationDigest(revocation);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'revocation',
        requestId,
        expectedRevocationDigest,
        revocation,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  async registerActionApproval(
    actionApproval: AccordLockActionApproval
  ): Promise<AccordLockActionApprovalRecord> {
    validateActionApproval(actionApproval);
    if (this.closedError) {
      return Promise.reject(this.closedError);
    }
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'REGISTER_ACTION_APPROVAL',
      action_approval: actionApproval,
    });
    const expectedApprovalDigest = actionApprovalDigest(actionApproval);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'action-approval',
        requestId,
        expectedApprovalDigest,
        actionApproval,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  async prepareFileRestore(
    recoveryId: string
  ): Promise<AccordLockFileRestorePreparation | AccordLockFileRestoreRecord> {
    if (!canonicalUuid(recoveryId)) {
      return Promise.reject(new Error('AccordLock recovery identifier is invalid'));
    }
    if (this.closedError) return Promise.reject(this.closedError);
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'PREPARE_FILE_RESTORE',
      file_restore_prepare: {
        schema_version: RUNTIME_PROTOCOL_VERSION,
        recovery_id: recoveryId,
      },
    });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'file-restore-prepare',
        requestId,
        recoveryId,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  async commitFileRestore(
    challenge: AccordLockFileRestoreChallenge
  ): Promise<AccordLockFileRestoreRecord> {
    validateFileRestoreChallenge(challenge);
    if (this.closedError) return Promise.reject(this.closedError);
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const challengeHash = accordLockFileRestoreChallengeDigest(challenge);
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'COMMIT_FILE_RESTORE',
      file_restore_commit: {
        schema_version: RUNTIME_PROTOCOL_VERSION,
        restore_id: challenge.restore_id,
        recovery_id: challenge.recovery_id,
        challenge_hash: challengeHash,
      },
    });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'file-restore-commit',
        requestId,
        challenge,
        challengeHash,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  async getSessionAudit(
    sessionId: string,
    offset = 0,
    limit = MAX_AUDIT_PAGE_EVENTS,
    snapshotRevision: number | null = null
  ): Promise<AccordLockSessionAuditPage> {
    if (
      !boundedText(sessionId, 256) ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      offset > MAX_AUDIT_OFFSET ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > MAX_AUDIT_PAGE_EVENTS ||
      (snapshotRevision !== null &&
        (!Number.isSafeInteger(snapshotRevision) || snapshotRevision < 0)) ||
      (offset === 0 && snapshotRevision !== null) ||
      (offset > 0 && snapshotRevision === null)
    ) {
      return Promise.reject(new Error('AccordLock audit query is outside the bounded profile'));
    }
    if (this.closedError) return Promise.reject(this.closedError);
    if (this.pending) {
      return Promise.reject(
        new Error('AccordLock control channel already has a request in flight')
      );
    }
    const requestId = this.requestIdFactory();
    if (!canonicalUuid(requestId)) {
      return Promise.reject(
        new Error('AccordLock control request factory returned an invalid UUID')
      );
    }
    const frame = encodeControlFrame({
      schema_version: RUNTIME_PROTOCOL_VERSION,
      request_id: requestId,
      method: 'GET_SESSION_AUDIT',
      audit_query: {
        schema_version: RUNTIME_PROTOCOL_VERSION,
        session_id: sessionId,
        offset,
        limit,
        snapshot_revision: snapshotRevision,
      },
    });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`AccordLock control request ${requestId} timed out`));
      }, this.requestTimeoutMs);
      this.pending = {
        kind: 'audit',
        requestId,
        sessionId,
        offset,
        limit,
        snapshotRevision,
        resolve,
        reject,
        timer,
      };
      try {
        this.input.write(frame, (error?: Error | null) => {
          if (error) {
            this.fail(new Error(`AccordLock control channel write failed: ${error.message}`));
          }
        });
      } catch (error) {
        this.fail(new Error(`AccordLock control channel write failed: ${errorMessage(error)}`));
      }
    });
  }

  consume(chunk: Buffer): void {
    if (this.closedError || chunk.length === 0) {
      return;
    }
    if (
      this.buffer.length + chunk.length >
      ACCORDLOCK_CONTROL_MAX_FRAME_BYTES + CONTROL_HEADER_BYTES
    ) {
      this.fail(new Error('AccordLock control response exceeds the bounded frame profile'));
      return;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= CONTROL_HEADER_BYTES) {
      if (!this.buffer.subarray(0, CONTROL_MAGIC_BYTES.length).equals(CONTROL_MAGIC_BYTES)) {
        this.fail(new Error('AccordLock control response has invalid frame magic'));
        return;
      }
      const bodyLength = this.buffer.readUInt32BE(CONTROL_MAGIC_BYTES.length);
      if (bodyLength > ACCORDLOCK_CONTROL_MAX_FRAME_BYTES) {
        this.fail(new Error('AccordLock control response declares an oversized frame'));
        return;
      }
      const frameLength = CONTROL_HEADER_BYTES + bodyLength;
      if (this.buffer.length < frameLength) {
        return;
      }
      const body = this.buffer.subarray(CONTROL_HEADER_BYTES, frameLength);
      this.buffer = this.buffer.subarray(frameLength);
      let response: ControlResponse;
      try {
        response = parseControlResponse(body);
      } catch (error) {
        this.fail(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      this.accept(response);
      if (this.closedError) {
        return;
      }
    }
  }

  fail(error: Error): void {
    if (this.closedError) {
      return;
    }
    this.closedError = error;
    this.buffer = Buffer.alloc(0);
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(error);
      this.pending = null;
    }
    this.onFatal(error);
  }

  shutdown(error: Error): void {
    if (this.closedError) {
      return;
    }
    this.closedError = error;
    this.buffer = Buffer.alloc(0);
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(error);
      this.pending = null;
    }
  }

  private accept(response: ControlResponse): void {
    if (response.request_id === null) {
      this.fail(new Error(`AccordLock control channel terminated: ${response.code}`));
      return;
    }
    if (!this.pending || response.request_id !== this.pending.requestId) {
      this.fail(new Error('AccordLock control response does not match the in-flight request'));
      return;
    }
    const pending = this.pending;
    this.pending = null;
    clearTimeout(pending.timer);
    const responseKind =
      'page' in response
        ? 'audit'
        : 'revocation_digest' in response
          ? 'revocation'
          : 'approval_id' in response
            ? 'action-approval'
            : 'record' in response
              ? 'file-restore'
              : 'approval';
    const pendingKind = pending.kind.startsWith('file-restore') ? 'file-restore' : pending.kind;
    if (pendingKind !== responseKind) {
      const error = new Error(
        `AccordLock control response type does not match the ${pending.kind} request`
      );
      pending.reject(error);
      this.fail(error);
      return;
    }
    if (response.status === 'ERROR') {
      const operation =
        pending.kind === 'approval'
          ? 'approval'
          : pending.kind === 'revocation'
            ? 'revocation'
            : pending.kind === 'action-approval'
              ? 'action approval'
              : pending.kind === 'audit'
                ? 'audit query'
                : 'file restore';
      pending.reject(new Error(`AccordLock ${operation} rejected: ${response.code}`));
      return;
    }

    if (pending.kind === 'audit') {
      if (!('page' in response) || response.page === null) {
        const error = new Error(
          'AccordLock control acknowledgement type does not match the audit request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      try {
        validateSessionAuditPage(
          response.page,
          pending.sessionId,
          pending.offset,
          pending.limit,
          pending.snapshotRevision
        );
      } catch (error) {
        const failure = error instanceof Error ? error : new Error(String(error));
        pending.reject(failure);
        this.fail(failure);
        return;
      }
      pending.resolve(response.page);
      return;
    }

    if (pending.kind === 'approval') {
      if (!('approval_digest' in response)) {
        const error = new Error(
          'AccordLock control acknowledgement type does not match the approval request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      if (response.approval_digest !== pending.expectedApprovalDigest) {
        const error = new Error(
          'AccordLock approval acknowledgement digest does not match the request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      pending.resolve({
        requestId: pending.requestId,
        code: response.code as AccordLockAuthorizationRecord['code'],
        approvalDigest: response.approval_digest as string,
      });
      return;
    }

    if (pending.kind === 'action-approval') {
      if (!('approval_id' in response)) {
        const error = new Error(
          'AccordLock control acknowledgement type does not match the action approval request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      if (
        response.approval_digest !== pending.expectedApprovalDigest ||
        response.approval_id !== pending.actionApproval.approval_id ||
        response.proposal_digest !== pending.actionApproval.proposal_digest ||
        response.approval_request_hash !== pending.actionApproval.approval_request_hash
      ) {
        const error = new Error(
          'AccordLock action approval acknowledgement identity or digest does not match the request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      pending.resolve({
        requestId: pending.requestId,
        code: response.code as AccordLockActionApprovalRecord['code'],
        approvalDigest: response.approval_digest as string,
        approvalId: response.approval_id as string,
        proposalDigest: response.proposal_digest as string,
        approvalRequestHash: response.approval_request_hash as string,
      });
      return;
    }

    if (pending.kind === 'file-restore-prepare' || pending.kind === 'file-restore-commit') {
      if (!('record' in response) || response.challenge_hash === null) {
        const error = new Error(
          'AccordLock control acknowledgement type does not match the file restore request'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }

      if (response.challenge !== null) {
        if (
          pending.kind !== 'file-restore-prepare' ||
          response.challenge.recovery_id !== pending.recoveryId ||
          response.challenge_hash !== accordLockFileRestoreChallengeDigest(response.challenge)
        ) {
          const error = new Error(
            'AccordLock file restore preparation does not match the requested recovery copy'
          );
          pending.reject(error);
          this.fail(error);
          return;
        }
        pending.resolve({
          requestId: pending.requestId,
          code: response.code as AccordLockFileRestorePreparation['code'],
          challengeHash: response.challenge_hash,
          challenge: response.challenge,
        });
        return;
      }

      if (response.record === null || response.record_hash === null) {
        const error = new Error('AccordLock file restore acknowledgement omitted its record');
        pending.reject(error);
        this.fail(error);
        return;
      }
      const expectedRecoveryId =
        pending.kind === 'file-restore-prepare'
          ? pending.recoveryId
          : pending.challenge.recovery_id;
      if (
        response.record.recovery_id !== expectedRecoveryId ||
        response.record.challenge_hash !== response.challenge_hash ||
        (pending.kind === 'file-restore-commit' &&
          (response.challenge_hash !== pending.challengeHash ||
            response.record.restore_id !== pending.challenge.restore_id ||
            response.record.session_id !== pending.challenge.session_id ||
            response.record.task_id !== pending.challenge.task_id ||
            response.record.run_id !== pending.challenge.run_id ||
            response.record.original_record_id !== pending.challenge.original_record_id ||
            response.record.original_record_hash !== pending.challenge.original_record_hash ||
            response.record.workspace_root !== pending.challenge.workspace_root ||
            response.record.relative_path !== pending.challenge.relative_path ||
            response.record.content_sha256 !== pending.challenge.content_sha256 ||
            response.record.original_bytes !== pending.challenge.original_bytes))
      ) {
        const error = new Error(
          'AccordLock file restore record does not match the exact prepared challenge'
        );
        pending.reject(error);
        this.fail(error);
        return;
      }
      pending.resolve({
        requestId: pending.requestId,
        code: response.code as AccordLockFileRestoreRecord['code'],
        challengeHash: response.challenge_hash,
        recordHash: response.record_hash,
        record: response.record,
      });
      return;
    }

    if (!('revocation_digest' in response)) {
      const error = new Error(
        'AccordLock control acknowledgement type does not match the revocation request'
      );
      pending.reject(error);
      this.fail(error);
      return;
    }
    if (
      response.revocation_digest !== pending.expectedRevocationDigest ||
      response.task_id !== pending.revocation.task_id ||
      response.session_id !== pending.revocation.session_id ||
      response.run_id !== pending.revocation.run_id
    ) {
      const error = new Error(
        'AccordLock revocation acknowledgement identity or digest does not match the request'
      );
      pending.reject(error);
      this.fail(error);
      return;
    }
    pending.resolve({
      requestId: pending.requestId,
      code: response.code as AccordLockRevocationRecord['code'],
      revocationDigest: response.revocation_digest as string,
      taskId: response.task_id as string,
      sessionId: response.session_id as string,
      runId: response.run_id as string,
    });
  }
}

const waitForProcessClose = (child: ChildProcess, timeoutMs: number): Promise<boolean> =>
  new Promise((resolve) => {
    let settled = false;
    const finish = (closed: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      child.off('close', onClose);
      resolve(closed);
    };
    const onClose = () => finish(true);
    const timeout = setTimeout(() => finish(false), timeoutMs);
    child.once('close', onClose);
  });

export const startAccordLockRuntime = async ({
  binDirectory,
  dataDirectory,
  logger,
  readinessFetch = fetch,
  startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
  shutdownTimeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
  controlRequestTimeoutMs = DEFAULT_CONTROL_REQUEST_TIMEOUT_MS,
  onUnexpectedExit,
  spawnProcess = spawn,
  tokenFactory = generateAccordLockRuntimeToken,
  controlRequestIdFactory = randomUUID,
  platform = process.platform,
  acceptDirtyDevelopmentMarker = false,
  expectedBinarySha256,
  terminalPrograms = [],
  networkDomains = [],
}: StartAccordLockRuntimeOptions): Promise<AccordLockRuntimeHandle> => {
  if (!Number.isSafeInteger(controlRequestTimeoutMs) || controlRequestTimeoutMs < 1) {
    throw new Error('AccordLock control request timeout must be a positive integer');
  }
  const bundle = resolveAccordLockRuntimeBundle(
    binDirectory,
    platform,
    acceptDirtyDevelopmentMarker,
    expectedBinarySha256
  );
  const token = tokenFactory();
  const launch = buildAccordLockRuntimeLaunchSpec(
    bundle,
    token,
    dataDirectory,
    process.env,
    terminalPrograms,
    networkDomains
  );
  const child = spawnProcess(launch.command, launch.args, launch.options);
  if (!child.stdin || !child.stdout) {
    try {
      child.kill('SIGKILL');
    } catch {
      // A failed spawn may not have a live process to terminate.
    }
    throw new Error('AccordLock runtime requires dedicated stdin/stdout control pipes');
  }
  const controlInput = child.stdin;
  const runtimeOutput = child.stdout;
  let readinessBuffer = Buffer.alloc(0);
  let sawReadiness = false;
  let exited = false;
  let stopping = false;
  let ready = false;
  let exitCode: number | null = null;
  let exitSignal: ChildProcess['signalCode'] = null;
  let cleanupPromise: Promise<void> | null = null;

  // The trusted runtime receives the launch bearer in its environment. Never
  // forward its raw stderr into application logs, even if a faulty runtime
  // accidentally prints its environment.
  child.stderr?.resume();

  let resolveReadyLine: (url: string) => void = () => {};
  let rejectReadyLine: (error: Error) => void = () => {};
  const readyLine = new Promise<string>((resolve, reject) => {
    resolveReadyLine = resolve;
    rejectReadyLine = reject;
  });

  const controlChannel = new AccordLockControlChannelClient(
    controlInput,
    controlRequestTimeoutMs,
    controlRequestIdFactory,
    (error) => {
      rejectReadyLine(error);
      if (!stopping && !exited) {
        try {
          child.kill('SIGTERM');
        } catch {
          // The process may already be terminating after closing its channel.
        }
      }
    }
  );
  let controlCommandTail: Promise<void> | null = null;
  const enqueueControlCommand = <T>(operation: () => Promise<T>): Promise<T> => {
    // Start the first command synchronously so its expected response binding is
    // installed before this method returns. Later commands wait for the exact
    // prior command to settle, including after a request-level failure.
    const result = controlCommandTail ? controlCommandTail.then(operation, operation) : operation();
    const completion = result.then(
      () => undefined,
      () => undefined
    );
    controlCommandTail = completion;
    void completion.then(() => {
      if (controlCommandTail === completion) controlCommandTail = null;
    });
    return result;
  };

  const onStdout = (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (sawReadiness) {
      controlChannel.consume(bytes);
      return;
    }
    readinessBuffer = Buffer.concat([readinessBuffer, bytes]);
    const newline = readinessBuffer.indexOf(0x0a);
    if (newline < 0) {
      if (readinessBuffer.length > MAX_READY_LINE_BYTES) {
        controlChannel.fail(new Error('AccordLock runtime did not emit a bounded ready line'));
      }
      return;
    }
    if (newline > MAX_READY_LINE_BYTES) {
      controlChannel.fail(new Error('AccordLock runtime ready line is too large'));
      return;
    }

    let lineBytes = readinessBuffer.subarray(0, newline);
    if (lineBytes.length > 0 && lineBytes[lineBytes.length - 1] === 0x0d) {
      lineBytes = lineBytes.subarray(0, lineBytes.length - 1);
    }
    const remaining = readinessBuffer.subarray(newline + 1);
    readinessBuffer = Buffer.alloc(0);
    if (lineBytes.some((byte) => byte > 0x7f)) {
      controlChannel.fail(new Error('AccordLock runtime ready line must be ASCII'));
      return;
    }
    try {
      const runtimeUrl = parseAccordLockRuntimeReadyLine(lineBytes.toString('ascii'));
      if (!runtimeUrl) {
        throw new Error('AccordLock runtime emitted unexpected stdout before readiness');
      }
      sawReadiness = true;
      resolveReadyLine(runtimeUrl);
      if (remaining.length > 0) {
        controlChannel.consume(remaining);
      }
    } catch (error) {
      controlChannel.fail(error instanceof Error ? error : new Error(String(error)));
    }
  };
  runtimeOutput.on('data', onStdout);
  runtimeOutput.once('end', () => {
    controlChannel.fail(new Error('AccordLock runtime control output closed'));
  });
  runtimeOutput.once('error', (error) => {
    controlChannel.fail(new Error(`AccordLock runtime control output failed: ${error.message}`));
  });
  controlInput.once('error', (error) => {
    controlChannel.fail(new Error(`AccordLock runtime control input failed: ${error.message}`));
  });

  child.on('exit', (code, signal) => {
    exited = true;
    exitCode = code;
    exitSignal = signal;
    controlChannel.shutdown(
      new Error(`AccordLock runtime control channel closed (code ${code}, signal ${signal})`)
    );
    if (!ready) {
      rejectReadyLine(
        new Error(`AccordLock runtime exited before readiness (code ${code}, signal ${signal})`)
      );
    } else if (!stopping) {
      try {
        onUnexpectedExit?.({ code, signal });
      } catch (error) {
        logger.error(`AccordLock runtime exit handler failed: ${errorMessage(error)}`);
      }
    }
  });
  child.on('error', (error) => {
    controlChannel.fail(new Error(`AccordLock runtime could not start: ${error.message}`));
  });

  const cleanup = async (): Promise<void> => {
    if (cleanupPromise) {
      return cleanupPromise;
    }
    cleanupPromise = (async () => {
      stopping = true;
      controlChannel.shutdown(new Error('AccordLock runtime is stopping'));
      if (!controlInput.destroyed && !controlInput.writableEnded) {
        try {
          controlInput.end();
        } catch {
          // Signal fallback below still terminates a broken pipe/process.
        }
      }
      if (exited) {
        return;
      }

      if (await waitForProcessClose(child, shutdownTimeoutMs)) {
        return;
      }
      try {
        child.kill('SIGTERM');
      } catch {
        // The process may have exited between the state check and signal delivery.
      }
      if (await waitForProcessClose(child, 1_000)) {
        return;
      }
      try {
        child.kill('SIGKILL');
      } catch {
        // There is nothing left to stop if the process exited concurrently.
      }
      await waitForProcessClose(child, 1_000);
    })();
    return cleanupPromise;
  };

  try {
    const deadline = Date.now() + startupTimeoutMs;
    let startupTimer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      startupTimer = setTimeout(
        () => reject(new Error('AccordLock runtime readiness timed out')),
        startupTimeoutMs
      );
    });
    let runtimeUrl: string;
    try {
      runtimeUrl = await Promise.race([readyLine, timeout]);
    } finally {
      if (startupTimer) {
        clearTimeout(startupTimer);
      }
    }

    let healthy = false;
    while (!exited && !controlChannel.isClosed && Date.now() < deadline) {
      if (await probeRuntimeHealth(runtimeUrl, token, readinessFetch)) {
        healthy = true;
        break;
      }
      await delay(100);
    }
    if (!healthy) {
      throw new Error('AccordLock runtime failed its authenticated readiness check');
    }
    if (exited) {
      throw new Error('AccordLock runtime exited immediately after its readiness check');
    }
    if (controlChannel.isClosed) {
      throw (
        controlChannel.failure ?? new Error('AccordLock runtime control channel is unavailable')
      );
    }

    ready = true;
    logger.info(
      `AccordLock runtime ${bundle.marker.source_commit.slice(0, 12)} is ready at ${runtimeUrl}`
    );
    return {
      runtimeUrl,
      process: child,
      authorizeTask: (approvedSession) =>
        enqueueControlCommand(() => controlChannel.authorizeTask(approvedSession)),
      revokeSession: (revocation) =>
        enqueueControlCommand(() => controlChannel.revokeSession(revocation)),
      registerActionApproval: (actionApproval) =>
        enqueueControlCommand(() => controlChannel.registerActionApproval(actionApproval)),
      prepareFileRestore: (recoveryId) =>
        enqueueControlCommand(() => controlChannel.prepareFileRestore(recoveryId)),
      commitFileRestore: (challenge) =>
        enqueueControlCommand(() => controlChannel.commitFileRestore(challenge)),
      getSessionAudit: (sessionId, offset, limit, snapshotRevision) =>
        enqueueControlCommand(() =>
          controlChannel.getSessionAudit(sessionId, offset, limit, snapshotRevision)
        ),
      forwardPolicyRequest: (requestPath, method, body) =>
        forwardRuntimeRequest(runtimeUrl, token, readinessFetch, requestPath, method, body),
      cleanup,
      hasExited: () => exited,
      getExitDetails: () => ({ code: exitCode, signal: exitSignal }),
    };
  } catch (error) {
    runtimeOutput.off('data', onStdout);
    runtimeOutput.resume();
    await cleanup();
    logger.error(`AccordLock runtime startup failed: ${errorMessage(error)}`);
    throw new Error(`AccordLock runtime startup failed: ${errorMessage(error)}`);
  }
};

/**
 * Reads one page from a stopped execution log through the dedicated Rust
 * audit-only process. This process receives no runtime bearer, starts no HTTP
 * listener, and is closed after the single bounded response.
 */
export const readAccordLockHistoricalAuditPage = async ({
  binDirectory,
  dataDirectory,
  expectedTaskId,
  expectedSessionId,
  expectedRunId,
  offset,
  limit,
  snapshotRevision,
  logger,
  shutdownTimeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
  controlRequestTimeoutMs = DEFAULT_CONTROL_REQUEST_TIMEOUT_MS,
  spawnProcess = spawn,
  controlRequestIdFactory = randomUUID,
  platform = process.platform,
  acceptDirtyDevelopmentMarker = false,
  expectedBinarySha256,
}: ReadAccordLockHistoricalAuditOptions): Promise<AccordLockSessionAuditPage> => {
  if (
    !canonicalUuid(expectedTaskId) ||
    !boundedText(expectedSessionId, 256) ||
    !SHA256_DIGEST.test(expectedRunId) ||
    !Number.isSafeInteger(controlRequestTimeoutMs) ||
    controlRequestTimeoutMs < 1 ||
    !Number.isSafeInteger(shutdownTimeoutMs) ||
    shutdownTimeoutMs < 1
  ) {
    throw new Error('Historical AccordLock audit binding is invalid');
  }
  const bundle = resolveAccordLockRuntimeBundle(
    binDirectory,
    platform,
    acceptDirtyDevelopmentMarker,
    expectedBinarySha256
  );
  const launch = buildAccordLockHistoricalAuditLaunchSpec(bundle, dataDirectory);
  const child = spawnProcess(launch.command, launch.args, launch.options);
  if (!child.stdin || !child.stdout) {
    try {
      child.kill('SIGKILL');
    } catch {
      // A failed spawn may not have a live process to terminate.
    }
    throw new Error('Historical AccordLock audit requires dedicated control pipes');
  }
  const input = child.stdin;
  const output = child.stdout;
  let exited = false;
  let stopping = false;
  let cleanupPromise: Promise<void> | null = null;
  child.stderr?.resume();

  const controlChannel = new AccordLockControlChannelClient(
    input,
    controlRequestTimeoutMs,
    controlRequestIdFactory,
    () => {
      if (!stopping && !exited) {
        try {
          child.kill('SIGTERM');
        } catch {
          // The process may already be closing its audit-only channel.
        }
      }
    }
  );
  output.on('data', (chunk: Buffer | string) => {
    controlChannel.consume(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  });
  output.once('end', () => {
    controlChannel.shutdown(new Error('Historical AccordLock audit output closed'));
  });
  output.once('error', (error) => {
    controlChannel.fail(new Error(`Historical AccordLock audit output failed: ${error.message}`));
  });
  input.once('error', (error) => {
    controlChannel.fail(new Error(`Historical AccordLock audit input failed: ${error.message}`));
  });
  child.once('error', (error) => {
    controlChannel.fail(new Error(`Historical AccordLock audit could not start: ${error.message}`));
  });
  child.once('exit', (code, signal) => {
    exited = true;
    controlChannel.shutdown(
      new Error(`Historical AccordLock audit closed (code ${code}, signal ${signal})`)
    );
  });

  const cleanup = async (): Promise<void> => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      stopping = true;
      controlChannel.shutdown(new Error('Historical AccordLock audit is stopping'));
      if (!input.destroyed && !input.writableEnded) input.end();
      if (exited || (await waitForProcessClose(child, shutdownTimeoutMs))) return;
      try {
        child.kill('SIGTERM');
      } catch {
        // The process may have exited between the check and signal delivery.
      }
      if (await waitForProcessClose(child, 1_000)) return;
      try {
        child.kill('SIGKILL');
      } catch {
        // Nothing remains to stop after a concurrent exit.
      }
      await waitForProcessClose(child, 1_000);
    })();
    return cleanupPromise;
  };

  try {
    const page = await controlChannel.getSessionAudit(
      expectedSessionId,
      offset,
      limit,
      snapshotRevision
    );
    if (
      page.task_id !== expectedTaskId ||
      page.session_id !== expectedSessionId ||
      page.run_id !== expectedRunId
    ) {
      throw new Error('Historical AccordLock audit does not match its protected locator');
    }
    return page;
  } catch (error) {
    logger.error(`Historical AccordLock audit failed: ${errorMessage(error)}`);
    throw error;
  } finally {
    await cleanup();
  }
};
