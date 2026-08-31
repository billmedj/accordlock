import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { AccordLockApprovalRequest as ProxyApprovalRequest } from './accordlockApprovalProxy';
import type {
  AccordLockActionApproval,
  AccordLockApprovalDecision,
  ApprovedSession,
} from './accordlockRuntime';

const FILESYSTEM_EXECUTE_PATH = '/api/v2/execution/filesystem/authorize-and-execute' as const;
const TERMINAL_EXECUTE_PATH = '/api/v2/execution/terminal/authorize-and-execute' as const;
const NETWORK_EXECUTE_PATH = '/api/v2/execution/network/authorize-and-execute' as const;
const APPROVAL_REQUEST_DIGEST_DOMAIN = 'accordlock:v2:action-approval-request';
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_PREVIEW_CHARACTERS = 1_600;
const MAX_OBJECTIVE_PREVIEW_CHARACTERS = 700;
// Must stay aligned with MAX_BROKERED_CONTENT_BYTES in the protected Goose
// filesystem boundary. The UI never advertises authority the broker cannot carry.
const MAX_REVIEWABLE_FILE_BYTES = 256 * 1024;
const MAX_REVIEWABLE_TERMINAL_ARGUMENT_BYTES = 64 * 1024;
const APPROVAL_LIFETIME_SECONDS = 2 * 60;

type JsonRecord = Record<string, unknown>;
type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

interface AccordLockActionRequestBase {
  relative_path: string;
  requested_bytes: number;
}

export type AccordLockActionRequest = AccordLockActionRequestBase &
  (
    | {
        extension_id: 'developer';
        tool_name: 'write' | 'edit';
        action_type: 'CREATE_FILE' | 'OVERWRITE_FILE' | 'EDIT_FILE';
      }
    | {
        extension_id: 'developer';
        tool_name: 'delete_file';
        action_type: 'DELETE_FILE';
      }
    | {
        extension_id: 'developer';
        tool_name: 'shell';
        action_type: 'EXECUTE_PROCESS';
        executable_path: string;
        executable_sha256: string;
      }
    | {
        extension_id: 'accordlock_network';
        tool_name: 'https_request';
        action_type: 'HTTPS_REQUEST';
      }
  );

export interface AccordLockActionApprovalRequest {
  schema_version: 2;
  task_id: string;
  session_id: string;
  run_id: string;
  tool_call_id: string;
  proposal_digest: string;
  task_policy_hash: string;
  prestate_hash: string;
  action: AccordLockActionRequest;
  task_requirement: Readonly<Record<string, unknown>>;
  transformation_step: Readonly<Record<string, unknown>>;
  policy_decision: Readonly<Record<string, unknown>>;
  policy_decision_hash: string;
}

type ActionArguments =
  | { kind: 'write'; path: string; content: string }
  | { kind: 'edit'; path: string; before: string; after: string }
  | { kind: 'delete_file'; path: string }
  | {
      kind: 'shell';
      path: string;
      argv: string[];
      env: Record<string, string>;
      timeoutSeconds: number;
      maxOutputBytes: number;
    }
  | {
      kind: 'https_request';
      path: string;
      method: 'GET' | 'HEAD';
      url: string;
      timeoutSeconds: number;
      maxResponseBytes: number;
    };

export interface AccordLockActionApprovalChallenge {
  sessionId: string;
  workspaceRoot: string;
  proposalDigest: string;
  approvalRequestHash: string;
  approvalRequest: AccordLockActionApprovalRequest;
  arguments: ActionArguments;
  operationLabel:
    | 'Create file'
    | 'Replace file'
    | 'Edit file'
    | 'Move file to recovery storage'
    | 'Run program'
    | 'Read website';
  targetLabel: 'Path' | 'Working directory' | 'Destination';
  target: string;
  quantityLabel: 'Proposed UTF-8' | 'Current file' | 'Direct arguments' | 'Response limit';
  contentEvidence: string;
  preview: string;
  previewTruncated: boolean;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function hasAllowedKeys(
  value: JsonRecord,
  allowed: readonly string[],
  required: readonly string[]
): boolean {
  const keys = Object.keys(value);
  return (
    keys.every((key) => allowed.includes(key)) &&
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function boundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    // Protocol text excludes C0/C1 controls. File contents are validated separately.
    // eslint-disable-next-line no-control-regex
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function nonzeroDigest(value: unknown): value is string {
  return (
    typeof value === 'string' && SHA256_DIGEST.test(value) && value !== `sha256:${'0'.repeat(64)}`
  );
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new Error('AccordLock approval request contains non-canonical JSON');
}

function plainDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreeze(nested);
    }
    Object.freeze(value);
  }
  return value;
}

export function accordLockActionApprovalRequestDigest(
  approvalRequest: AccordLockActionApprovalRequest
): string {
  const canonical = Buffer.from(canonicalJson(approvalRequest), 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(canonical.length));
  return `sha256:${createHash('sha256')
    .update(APPROVAL_REQUEST_DIGEST_DOMAIN, 'ascii')
    .update(Buffer.from([0]))
    .update(length)
    .update(canonical)
    .digest('hex')}`;
}

function parseJsonBytes(bytes: Uint8Array, label: string): unknown {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`AccordLock ${label} is malformed`);
  }
}

function validateRelativePath(value: unknown): value is string {
  return (
    boundedText(value, 4_096) &&
    !/[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff]/u.test(value) &&
    value !== '.' &&
    !value.startsWith('/') &&
    !value.includes('\\') &&
    !value.includes(':') &&
    !value
      .split('/')
      .some((component) => component.length === 0 || component === '.' || component === '..')
  );
}

function literalText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    // Terminal argv is literal data: spaces are meaningful, controls are not.
    // eslint-disable-next-line no-control-regex
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function parseTerminalArguments(value: JsonRecord): ActionArguments {
  if (
    !hasAllowedKeys(
      value,
      ['argv', 'cwd', 'env', 'timeout_seconds', 'max_output_bytes'],
      ['argv']
    ) ||
    !Array.isArray(value.argv) ||
    value.argv.length === 0 ||
    value.argv.length > 128 ||
    !value.argv.every((argument) => literalText(argument, 4_096)) ||
    typeof value.argv[0] !== 'string' ||
    !/^[a-z0-9_-]{1,64}$/u.test(value.argv[0])
  ) {
    throw new Error('AccordLock terminal arguments are malformed');
  }
  const cwd = value.cwd ?? '.';
  const env = value.env ?? {};
  const timeoutSeconds = value.timeout_seconds ?? 60;
  const maxOutputBytes = value.max_output_bytes ?? 64 * 1_024;
  if (
    typeof cwd !== 'string' ||
    (cwd !== '.' && !validateRelativePath(cwd)) ||
    !isRecord(env) ||
    Object.keys(env).length > 16 ||
    !Object.entries(env).every(
      ([name, entry]) => /^[A-Z][A-Z0-9_]{0,63}$/u.test(name) && literalText(entry, 256)
    ) ||
    !Number.isSafeInteger(timeoutSeconds) ||
    Number(timeoutSeconds) < 1 ||
    Number(timeoutSeconds) > 300 ||
    !Number.isSafeInteger(maxOutputBytes) ||
    Number(maxOutputBytes) < 1 ||
    Number(maxOutputBytes) > 256 * 1_024
  ) {
    throw new Error('AccordLock terminal arguments are malformed');
  }
  const argv = value.argv as string[];
  const totalArgumentBytes = argv.reduce(
    (total, argument) => total + Buffer.byteLength(argument, 'utf8'),
    0
  );
  if (totalArgumentBytes > 64 * 1_024) {
    throw new Error('AccordLock terminal arguments are malformed');
  }
  return deepFreeze({
    kind: 'shell',
    path: cwd,
    argv,
    env: env as Record<string, string>,
    timeoutSeconds: Number(timeoutSeconds),
    maxOutputBytes: Number(maxOutputBytes),
  });
}

function parseNetworkArguments(value: JsonRecord): ActionArguments {
  if (
    !hasExactKeys(value, [
      'method',
      'url',
      'headers',
      'body',
      'timeout_seconds',
      'max_response_bytes',
      'redirect_policy',
    ]) ||
    (value.method !== 'GET' && value.method !== 'HEAD') ||
    typeof value.url !== 'string' ||
    value.url.length === 0 ||
    Buffer.byteLength(value.url, 'utf8') > 4_096 ||
    !Array.isArray(value.headers) ||
    value.headers.length !== 0 ||
    value.body !== null ||
    value.redirect_policy !== 'DENY' ||
    !Number.isSafeInteger(value.timeout_seconds) ||
    Number(value.timeout_seconds) < 1 ||
    Number(value.timeout_seconds) > 120 ||
    !Number.isSafeInteger(value.max_response_bytes) ||
    Number(value.max_response_bytes) < 1 ||
    Number(value.max_response_bytes) > 256 * 1_024
  ) {
    throw new Error('AccordLock network arguments are malformed');
  }
  let parsed: URL;
  try {
    parsed = new URL(value.url);
  } catch {
    throw new Error('AccordLock network URL is malformed');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    (parsed.port !== '' && parsed.port !== '443') ||
    parsed.hash !== '' ||
    parsed.hostname !== parsed.hostname.toLowerCase() ||
    !parsed.hostname.includes('.') ||
    parsed.hostname === 'localhost' ||
    parsed.hostname.endsWith('.localhost') ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(parsed.hostname) ||
    parsed.hostname.includes(':')
  ) {
    throw new Error('AccordLock network URL is outside the approved profile');
  }
  return deepFreeze({
    kind: 'https_request',
    path: `${parsed.hostname}${parsed.pathname}${parsed.search}`,
    method: value.method,
    url: value.url,
    timeoutSeconds: Number(value.timeout_seconds),
    maxResponseBytes: Number(value.max_response_bytes),
  });
}

function parseActionArguments(
  extensionId: unknown,
  toolName: unknown,
  value: unknown
): ActionArguments {
  if (!isRecord(value)) throw new Error('AccordLock action arguments are malformed');
  if (toolName === 'write' && hasExactKeys(value, ['path', 'content'])) {
    if (!validateRelativePath(value.path) || typeof value.content !== 'string') {
      throw new Error('AccordLock write arguments are malformed');
    }
    return { kind: 'write', path: value.path, content: value.content };
  }
  if (toolName === 'edit' && hasExactKeys(value, ['path', 'before', 'after'])) {
    if (
      !validateRelativePath(value.path) ||
      typeof value.before !== 'string' ||
      value.before.length === 0 ||
      typeof value.after !== 'string'
    ) {
      throw new Error('AccordLock edit arguments are malformed');
    }
    return { kind: 'edit', path: value.path, before: value.before, after: value.after };
  }
  if (toolName === 'delete_file' && hasExactKeys(value, ['path'])) {
    if (!validateRelativePath(value.path)) {
      throw new Error('AccordLock delete-file arguments are malformed');
    }
    return { kind: 'delete_file', path: value.path };
  }
  if (extensionId === 'developer' && toolName === 'shell') {
    return parseTerminalArguments(value);
  }
  if (extensionId === 'accordlock_network' && toolName === 'https_request') {
    return parseNetworkArguments(value);
  }
  throw new Error('AccordLock approval request is not a supported protected action');
}

function isActionRequest(value: unknown): value is AccordLockActionRequest {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.requested_bytes) ||
    Number(value.requested_bytes) < 0
  ) {
    return false;
  }
  if (
    value.extension_id === 'developer' &&
    (value.tool_name === 'write' || value.tool_name === 'edit') &&
    hasExactKeys(value, [
      'extension_id',
      'tool_name',
      'relative_path',
      'action_type',
      'requested_bytes',
    ]) &&
    validateRelativePath(value.relative_path) &&
    ['CREATE_FILE', 'OVERWRITE_FILE', 'EDIT_FILE'].includes(String(value.action_type))
  ) {
    return true;
  }
  if (
    value.extension_id === 'developer' &&
    value.tool_name === 'delete_file' &&
    value.action_type === 'DELETE_FILE' &&
    hasExactKeys(value, [
      'extension_id',
      'tool_name',
      'relative_path',
      'action_type',
      'requested_bytes',
    ]) &&
    validateRelativePath(value.relative_path)
  ) {
    return true;
  }
  if (
    value.extension_id === 'developer' &&
    value.tool_name === 'shell' &&
    value.action_type === 'EXECUTE_PROCESS' &&
    hasExactKeys(value, [
      'extension_id',
      'tool_name',
      'relative_path',
      'action_type',
      'requested_bytes',
      'executable_path',
      'executable_sha256',
    ]) &&
    typeof value.relative_path === 'string' &&
    (value.relative_path === '.' || validateRelativePath(value.relative_path)) &&
    boundedText(value.executable_path, 4_096) &&
    /^(?:[A-Za-z]:[\\/]|\/)/u.test(value.executable_path) &&
    nonzeroDigest(value.executable_sha256)
  ) {
    return true;
  }
  if (
    value.extension_id === 'accordlock_network' &&
    value.tool_name === 'https_request' &&
    value.action_type === 'HTTPS_REQUEST' &&
    value.requested_bytes === 0 &&
    hasExactKeys(value, [
      'extension_id',
      'tool_name',
      'relative_path',
      'action_type',
      'requested_bytes',
    ]) &&
    boundedText(value.relative_path, 4_096)
  ) {
    return true;
  }
  return false;
}

function parseApprovalRequest(value: unknown): AccordLockActionApprovalRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'schema_version',
      'task_id',
      'session_id',
      'run_id',
      'tool_call_id',
      'proposal_digest',
      'task_policy_hash',
      'prestate_hash',
      'action',
      'task_requirement',
      'transformation_step',
      'policy_decision',
      'policy_decision_hash',
    ]) ||
    value.schema_version !== 2 ||
    typeof value.task_id !== 'string' ||
    !UUID.test(value.task_id) ||
    !boundedText(value.session_id, 256) ||
    !boundedText(value.run_id, 256) ||
    !boundedText(value.tool_call_id, 256) ||
    !nonzeroDigest(value.proposal_digest) ||
    !nonzeroDigest(value.task_policy_hash) ||
    !nonzeroDigest(value.prestate_hash) ||
    !isRecord(value.task_requirement) ||
    !isRecord(value.transformation_step) ||
    !isRecord(value.policy_decision) ||
    !nonzeroDigest(value.policy_decision_hash) ||
    !isActionRequest(value.action)
  ) {
    throw new Error('AccordLock runtime approval request is malformed');
  }
  return value as unknown as AccordLockActionApprovalRequest;
}

function validAgentPlanCheckpoint(
  value: unknown,
  proposal: Readonly<Record<string, unknown>>
): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'schema_version',
      'session_id',
      'run_id',
      'tool_call_id',
      'material',
      'material_sha256',
      'recorded_at',
    ]) &&
    value.schema_version === 1 &&
    value.session_id === proposal.session_id &&
    value.run_id === proposal.run_id &&
    value.tool_call_id === proposal.tool_call_id &&
    nonzeroDigest(value.material_sha256) &&
    plainDigest(value.material) === value.material_sha256 &&
    Number.isSafeInteger(value.recorded_at) &&
    (value.recorded_at as number) > 0 &&
    Buffer.byteLength(canonicalJson(value.material), 'utf8') <= 512 * 1_024
  );
}

export function sanitizeAccordLockDialogText(
  value: string,
  maximumCharacters = MAX_PREVIEW_CHARACTERS
): { text: string; truncated: boolean } {
  let text = '';
  let truncated = false;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const unsafeControl =
      (code < 0x20 && character !== '\n' && character !== '\t') ||
      (code >= 0x7f && code <= 0x9f) ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069);
    const addition = unsafeControl ? '�' : character;
    if (text.length + addition.length > maximumCharacters) {
      truncated = true;
      break;
    }
    text += addition;
  }
  return { text, truncated };
}

function proposalMatchesRoute(
  path: ProxyApprovalRequest['path'],
  extensionId: unknown,
  toolName: unknown
): boolean {
  if (path === FILESYSTEM_EXECUTE_PATH) {
    return (
      extensionId === 'developer' &&
      (toolName === 'write' || toolName === 'edit' || toolName === 'delete_file')
    );
  }
  if (path === TERMINAL_EXECUTE_PATH) {
    return extensionId === 'developer' && toolName === 'shell';
  }
  if (path === NETWORK_EXECUTE_PATH) {
    return extensionId === 'accordlock_network' && toolName === 'https_request';
  }
  return false;
}

export function parseAccordLockActionApprovalChallenge(
  request: ProxyApprovalRequest
): AccordLockActionApprovalChallenge {
  if (
    request.path !== FILESYSTEM_EXECUTE_PATH &&
    request.path !== TERMINAL_EXECUTE_PATH &&
    request.path !== NETWORK_EXECUTE_PATH
  ) {
    throw new Error('AccordLock cannot approve this runtime route');
  }
  const requestValue = parseJsonBytes(request.requestBody, 'protected-action request');
  if (
    !isRecord(requestValue) ||
    !hasExactKeys(requestValue, ['proposal', 'schema_version']) ||
    requestValue.schema_version !== 2 ||
    !isRecord(requestValue.proposal)
  ) {
    throw new Error('AccordLock protected-action request is malformed');
  }
  const proposal = requestValue.proposal;
  if (
    !hasExactKeys(proposal, [
      'schema_version',
      'session_id',
      'run_id',
      'tool_call_id',
      'workspace_root',
      'extension_id',
      'tool_name',
      'arguments',
      'arguments_sha256',
      'agent_plan_checkpoint',
    ]) ||
    proposal.schema_version !== 3 ||
    !boundedText(proposal.session_id, 256) ||
    !boundedText(proposal.run_id, 256) ||
    !boundedText(proposal.tool_call_id, 256) ||
    !boundedText(proposal.workspace_root, 4_096) ||
    !boundedText(proposal.extension_id, 256) ||
    !boundedText(proposal.tool_name, 256) ||
    !proposalMatchesRoute(request.path, proposal.extension_id, proposal.tool_name) ||
    !nonzeroDigest(proposal.arguments_sha256) ||
    plainDigest(proposal.arguments) !== proposal.arguments_sha256 ||
    !validAgentPlanCheckpoint(proposal.agent_plan_checkpoint, proposal)
  ) {
    throw new Error('AccordLock protected-action proposal is malformed');
  }
  const argumentsValue = parseActionArguments(
    proposal.extension_id,
    proposal.tool_name,
    proposal.arguments
  );

  const responseValue = parseJsonBytes(request.responseBody, 'runtime approval response');
  if (
    !isRecord(responseValue) ||
    !hasExactKeys(responseValue, [
      'schema_version',
      'proposal_digest',
      'status',
      'reason_code',
      'approval_request',
      'approval_request_hash',
    ]) ||
    responseValue.schema_version !== 2 ||
    responseValue.status !== 'APPROVAL_REQUIRED' ||
    responseValue.reason_code !== 'ACTION_APPROVAL_REQUIRED' ||
    !nonzeroDigest(responseValue.proposal_digest) ||
    !nonzeroDigest(responseValue.approval_request_hash)
  ) {
    throw new Error('AccordLock runtime did not return an exact approval request');
  }
  const approvalRequest = parseApprovalRequest(responseValue.approval_request);
  const proposalDigest = plainDigest(proposal);
  const approvalRequestHash = accordLockActionApprovalRequestDigest(approvalRequest);
  const requestedBytes =
    argumentsValue.kind === 'write'
      ? Buffer.byteLength(argumentsValue.content, 'utf8')
      : argumentsValue.kind === 'edit'
        ? Buffer.byteLength(argumentsValue.after, 'utf8')
        : argumentsValue.kind === 'delete_file'
          ? approvalRequest.action.requested_bytes
          : argumentsValue.kind === 'https_request'
            ? 0
            : [...argumentsValue.argv.slice(1), ...Object.values(argumentsValue.env)].reduce(
                (total, value) => total + Buffer.byteLength(value, 'utf8'),
                0
              );
  const expectedOperation =
    argumentsValue.kind === 'edit'
      ? 'EDIT_FILE'
      : argumentsValue.kind === 'delete_file'
        ? 'DELETE_FILE'
        : argumentsValue.kind === 'shell'
          ? 'EXECUTE_PROCESS'
          : argumentsValue.kind === 'https_request'
            ? 'HTTPS_REQUEST'
            : approvalRequest.action.action_type;
  if (
    proposalDigest !== responseValue.proposal_digest ||
    proposalDigest !== approvalRequest.proposal_digest ||
    approvalRequestHash !== responseValue.approval_request_hash ||
    approvalRequest.session_id !== proposal.session_id ||
    approvalRequest.run_id !== proposal.run_id ||
    approvalRequest.tool_call_id !== proposal.tool_call_id ||
    approvalRequest.action.extension_id !== proposal.extension_id ||
    approvalRequest.action.tool_name !== proposal.tool_name ||
    approvalRequest.action.relative_path !== argumentsValue.path ||
    approvalRequest.action.requested_bytes !== requestedBytes ||
    approvalRequest.action.action_type !== expectedOperation ||
    (proposal.tool_name === 'write' &&
      approvalRequest.action.action_type !== 'CREATE_FILE' &&
      approvalRequest.action.action_type !== 'OVERWRITE_FILE')
  ) {
    throw new Error('AccordLock runtime approval request does not match the exact tool request');
  }

  const contentEvidence =
    argumentsValue.kind === 'write'
      ? `Content ${plainDigest(argumentsValue.content)} · ${requestedBytes} bytes`
      : argumentsValue.kind === 'edit'
        ? `Find ${plainDigest(argumentsValue.before)} · replace with ${plainDigest(argumentsValue.after)}`
        : argumentsValue.kind === 'delete_file'
          ? `Exact current file state · ${requestedBytes} bytes · recoverable`
          : argumentsValue.kind === 'https_request'
            ? `${argumentsValue.method} · ${argumentsValue.maxResponseBytes} byte response limit · no credentials or redirects`
            : `Direct argv ${plainDigest(argumentsValue.argv)} · ${argumentsValue.argv.length} entries · no shell string`;
  const previewValue =
    argumentsValue.kind === 'write'
      ? argumentsValue.content
      : argumentsValue.kind === 'edit'
        ? `Before\n${argumentsValue.before}\n\nAfter\n${argumentsValue.after}`
        : argumentsValue.kind === 'delete_file'
          ? `Move ${argumentsValue.path} to AccordLock recovery storage. The original file can be restored from the recorded recovery path.`
          : argumentsValue.kind === 'https_request'
            ? [
                `${argumentsValue.method} ${argumentsValue.url}`,
                `timeout: ${argumentsValue.timeoutSeconds}s`,
                `maximum response: ${argumentsValue.maxResponseBytes} bytes`,
                'headers: none',
                'redirects: blocked',
              ].join('\n')
            : [
                'Direct argv (no shell):',
                ...argumentsValue.argv.map(
                  (argument, index) => `${index}: ${JSON.stringify(argument)}`
                ),
                `cwd: ${JSON.stringify(argumentsValue.path)}`,
                `env: ${canonicalJson(argumentsValue.env)}`,
                `timeout: ${argumentsValue.timeoutSeconds}s`,
              ].join('\n');
  const preview = sanitizeAccordLockDialogText(previewValue);
  return deepFreeze({
    sessionId: proposal.session_id,
    workspaceRoot: proposal.workspace_root,
    proposalDigest,
    approvalRequestHash,
    approvalRequest,
    arguments: argumentsValue,
    operationLabel:
      approvalRequest.action.action_type === 'CREATE_FILE'
        ? 'Create file'
        : approvalRequest.action.action_type === 'OVERWRITE_FILE'
          ? 'Replace file'
          : approvalRequest.action.action_type === 'EDIT_FILE'
            ? 'Edit file'
            : approvalRequest.action.action_type === 'DELETE_FILE'
              ? 'Move file to recovery storage'
              : approvalRequest.action.action_type === 'HTTPS_REQUEST'
                ? 'Read website'
                : 'Run program',
    targetLabel:
      argumentsValue.kind === 'shell'
        ? 'Working directory'
        : argumentsValue.kind === 'https_request'
          ? 'Destination'
          : 'Path',
    target: argumentsValue.path,
    quantityLabel:
      argumentsValue.kind === 'shell'
        ? 'Direct arguments'
        : argumentsValue.kind === 'https_request'
          ? 'Response limit'
          : argumentsValue.kind === 'delete_file'
            ? 'Current file'
            : 'Proposed UTF-8',
    contentEvidence,
    preview: preview.text,
    previewTruncated: preview.truncated,
  });
}

export function bindAccordLockActionApproval(
  challenge: AccordLockActionApprovalChallenge,
  approvedSession: DeepReadonly<ApprovedSession>,
  decision: AccordLockApprovalDecision,
  approvalId: string,
  decidedAt: number
): AccordLockActionApproval {
  if (
    !UUID.test(approvalId) ||
    !Number.isSafeInteger(decidedAt) ||
    decidedAt < approvedSession.approved_at ||
    decidedAt >= approvedSession.expires_at ||
    approvedSession.task_id !== challenge.approvalRequest.task_id ||
    approvedSession.session_id !== challenge.approvalRequest.session_id ||
    approvedSession.run_id !== challenge.approvalRequest.run_id ||
    approvedSession.workspace_root !== challenge.workspaceRoot ||
    approvedSession.task_policy_hash !== challenge.approvalRequest.task_policy_hash ||
    accordLockActionApprovalRequestDigest(challenge.approvalRequest) !==
      challenge.approvalRequestHash ||
    !approvedSession.capabilities.some(
      (capability) =>
        capability.extension_id === challenge.approvalRequest.action.extension_id &&
        capability.tool_name === challenge.approvalRequest.action.tool_name
    ) ||
    (decision !== 'APPROVED' && decision !== 'DENIED')
  ) {
    throw new Error('AccordLock approval does not match the authorized task');
  }
  const expiresAt = Math.min(decidedAt + APPROVAL_LIFETIME_SECONDS, approvedSession.expires_at);
  if (expiresAt <= decidedAt) {
    throw new Error('AccordLock approval cannot receive a valid single-use window');
  }
  const evidence = {
    schema_version: 2,
    approval_id: approvalId,
    approval_request_hash: challenge.approvalRequestHash,
    decision,
    decided_at: decidedAt,
  };
  return {
    schema_version: 2,
    approval_id: approvalId,
    task_id: challenge.approvalRequest.task_id,
    session_id: challenge.approvalRequest.session_id,
    run_id: challenge.approvalRequest.run_id,
    tool_call_id: challenge.approvalRequest.tool_call_id,
    proposal_digest: challenge.proposalDigest,
    task_policy_hash: challenge.approvalRequest.task_policy_hash,
    prestate_hash: challenge.approvalRequest.prestate_hash,
    approval_request_hash: challenge.approvalRequestHash,
    task_requirement: challenge.approvalRequest.task_requirement,
    transformation_step: challenge.approvalRequest.transformation_step,
    policy_decision: challenge.approvalRequest.policy_decision,
    policy_decision_hash: challenge.approvalRequest.policy_decision_hash,
    decision,
    approval_evidence_hash: plainDigest(evidence),
    decided_at: decidedAt,
    expires_at: expiresAt,
  };
}

export function formatAccordLockActionApprovalDetail(
  challenge: AccordLockActionApprovalChallenge,
  objective: string
): string {
  const objectivePreview = sanitizeAccordLockDialogText(
    objective,
    MAX_OBJECTIVE_PREVIEW_CHARACTERS
  );
  const proposedChange = sanitizeAccordLockDialogText(challenge.preview);
  const assurance = (() => {
    switch (String(challenge.approvalRequest.action.action_type)) {
      case 'CREATE_FILE':
      case 'OVERWRITE_FILE':
      case 'EDIT_FILE':
        return [
          'File prestate: exact state will be revalidated immediately before mutation',
          'Scope: one use, for this exact content only',
        ];
      case 'DELETE_FILE':
        return [
          'File prestate: exact state will be revalidated immediately before the move',
          'Recovery: the file is moved to protected recovery storage inside this workspace',
          'Scope: one use, for this exact regular file only; directories are never removed',
        ];
      case 'EXECUTE_PROCESS':
        if (
          !('executable_path' in challenge.approvalRequest.action) ||
          !('executable_sha256' in challenge.approvalRequest.action)
        ) {
          return ['Execution identity: unavailable — keep this action locked'];
        }
        return [
          `Executable: ${sanitizeAccordLockDialogText(String(challenge.approvalRequest.action.executable_path), 4_096).text}`,
          `Executable SHA-256: ${String(challenge.approvalRequest.action.executable_sha256)}`,
          'Execution authorization: executable, working directory, arguments, and environment are committed',
          'Warning: this execution is not sandboxed and may affect the system beyond this workspace',
          'Scope: one use for this exact request; executable path and hash are checked immediately before launch',
        ];
      case 'HTTPS_REQUEST':
        return [
          'Network authorization: exact request and destination are committed and revalidated',
          'Scope: one use, for this exact request only',
        ];
      default:
        return [
          'Action authorization: exact approved action is committed and revalidated',
          'Scope: one use, for this exact action only',
        ];
    }
  })();
  return [
    'TASK — USER PROVIDED',
    '─'.repeat(36),
    objectivePreview.text,
    objectivePreview.truncated ? '… task text shortened here' : '',
    '─'.repeat(36),
    '',
    'PROPOSED CHANGE — UNTRUSTED',
    '─'.repeat(36),
    proposedChange.text || '(empty content)',
    '─'.repeat(36),
    '',
    ...assurance,
  ]
    .filter((line) => line.length > 0)
    .join('\n');
}

/**
 * A positive decision is offered only when the trusted native review can render
 * the complete exact action. The Approval Center intentionally keeps a short
 * preview; every positive decision still opens the isolated main-process review
 * which renders `challenge.arguments` in full before producing authority.
 */
export function canApproveAccordLockAction(challenge: AccordLockActionApprovalChallenge): boolean {
  switch (challenge.arguments.kind) {
    case 'write':
      return Buffer.byteLength(challenge.arguments.content, 'utf8') <= MAX_REVIEWABLE_FILE_BYTES;
    case 'edit':
      return (
        Buffer.byteLength(challenge.arguments.before, 'utf8') +
          Buffer.byteLength(challenge.arguments.after, 'utf8') <=
        MAX_REVIEWABLE_FILE_BYTES
      );
    case 'delete_file':
      return true;
    case 'shell':
      return (
        challenge.arguments.argv.reduce(
          (total, argument) => total + Buffer.byteLength(argument, 'utf8'),
          0
        ) <= MAX_REVIEWABLE_TERMINAL_ARGUMENT_BYTES
      );
    case 'https_request':
      return true;
  }
}
