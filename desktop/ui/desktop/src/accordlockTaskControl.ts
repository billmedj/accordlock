import { createHash, randomUUID } from 'node:crypto';
import {
  accordLockObjectiveDigest,
  accordLockTaskPolicyDigest,
  type AccordLockCapability,
  type AccordLockTaskPolicy,
  type AccordLockRuntimeHandle,
  type ApprovedSession,
  type SessionRevocation,
} from './accordlockRuntime';
export type { ApprovedSession } from './accordlockRuntime';
import {
  ACCORDLOCK_CONTROL_PROTOCOL,
  type AccordLockTaskAccessSelection,
  type AccordLockTaskAuthorizationDecisionAck,
  type AccordLockTaskAuthorizationDecisionRequest,
  type AccordLockTaskCapability,
  type AccordLockTaskAuditRequest,
  type AccordLockTaskRequest,
  type AccordLockTaskRestoreRequest,
  type AccordLockTaskAuthorizationRevokeAck,
  type AccordLockTaskAuthorizationRevokeRequest,
  type AccordLockTaskAuthorization,
} from './accordlock/taskIpc';
import {
  accordLockAuditWorkspaceId,
  type AccordLockTaskAuditIndex,
  type AccordLockTaskAuditIndexEntry,
} from './accordlockTaskAuditIndex';

const TASK_AUTHORIZATION_LIFETIME_SECONDS = 8 * 60 * 60;
const MAX_OBJECTIVE_BYTES = 4_000;
const MAX_SESSION_ID_BYTES = 256;
const MAX_WORKSPACE_BYTES = 4_096;
const SHA256_IDENTIFIER = /^sha256:[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const APPROVED_CAPABILITIES = [
  { extension_id: 'developer', tool_name: 'delete_file' },
  { extension_id: 'developer', tool_name: 'edit' },
  { extension_id: 'developer', tool_name: 'read' },
  { extension_id: 'developer', tool_name: 'shell' },
  { extension_id: 'developer', tool_name: 'tree' },
  { extension_id: 'developer', tool_name: 'write' },
] as const;

const GOVERNED_NETWORK_CAPABILITY = {
  extension_id: 'accordlock_network',
  tool_name: 'https_request',
} as const;

const PRESENTED_CAPABILITIES = [
  { extension_id: 'developer', tool_name: 'read' },
  { extension_id: 'developer', tool_name: 'tree' },
  { extension_id: 'developer', tool_name: 'edit' },
  { extension_id: 'developer', tool_name: 'write' },
  { extension_id: 'developer', tool_name: 'delete_file' },
  { extension_id: 'developer', tool_name: 'shell' },
] as const;

const AUTOMATIC_CAPABILITIES = [
  { extension_id: 'developer', tool_name: 'read' },
  { extension_id: 'developer', tool_name: 'tree' },
] as const;

const PROTECTED_PATHS = [
  '.accordlock',
  '.env',
  '.git',
  '.goose',
  '.goosehints',
  '.ssh',
  'credentials',
] as const;

type CapabilityPresentation = Omit<AccordLockTaskCapability, 'extension_id' | 'tool_name'>;

const CAPABILITY_PRESENTATION = {
  'developer/read': {
    display_name: 'Read files',
    description: 'Read text files inside this workspace.',
    operation_type: 'READ',
  },
  'developer/tree': {
    display_name: 'Browse workspace',
    description: 'List files and folders inside this workspace.',
    operation_type: 'READ',
  },
  'developer/edit': {
    display_name: 'Edit files',
    description: 'Replace one exact text fragment only after single-use human approval.',
    operation_type: 'WRITE',
  },
  'developer/write': {
    display_name: 'Write files',
    description: 'Create or replace files only after single-use human approval.',
    operation_type: 'WRITE',
  },
  'developer/delete_file': {
    display_name: 'Move files to recovery storage',
    description:
      'Move one exact regular file to protected recovery storage only after single-use human approval.',
    operation_type: 'WRITE',
  },
  'developer/shell': {
    display_name: 'Run approved programs',
    description:
      'Run one exact direct-argument command only after single-use human approval; shell strings are never accepted.',
    operation_type: 'EXECUTE',
  },
  'accordlock_network/https_request': {
    display_name: 'Read approved websites',
    description:
      'Send one exact GET or HEAD request to a configured domain only after single-use human approval.',
    operation_type: 'NETWORK',
  },
} as const satisfies Record<string, CapabilityPresentation>;

function approvedCapabilities(governedNetworkEnabled: boolean): AccordLockCapability[] {
  return [
    ...(governedNetworkEnabled ? [GOVERNED_NETWORK_CAPABILITY] : []),
    ...APPROVED_CAPABILITIES,
  ].map((capability) => ({ ...capability }));
}

function projectApprovedCapabilities(
  governedNetworkEnabled: boolean
): AccordLockTaskAuthorization['capabilities'] {
  const capabilities = [
    ...(governedNetworkEnabled ? [GOVERNED_NETWORK_CAPABILITY] : []),
    ...PRESENTED_CAPABILITIES,
  ];
  return capabilities.map((capability) => {
    const key =
      `${capability.extension_id}/${capability.tool_name}` as keyof typeof CAPABILITY_PRESENTATION;
    return { ...capability, ...CAPABILITY_PRESENTATION[key] };
  });
}

function taskAccessAllows(
  selection: AccordLockTaskAccessSelection,
  capability: Pick<AccordLockCapability, 'extension_id' | 'tool_name'>
): boolean {
  if (capability.extension_id === 'accordlock_network') return true;
  if (capability.tool_name === 'shell') return selection.terminal === 'ASK';
  if (
    capability.tool_name === 'edit' ||
    capability.tool_name === 'write' ||
    capability.tool_name === 'delete_file'
  ) {
    return selection.file_changes === 'ASK';
  }
  return true;
}

interface TaskRecord {
  windowId: number;
  objective: string;
  reviewedAuthorizationDigest: string;
  authorization: AccordLockTaskAuthorization;
  approvedSession: ApprovedSession;
  decision: 'PENDING' | 'APPROVED' | 'REJECTED';
  acknowledgement: AccordLockTaskAuthorizationDecisionAck | null;
  inFlight: {
    decision: AccordLockTaskAuthorizationDecisionRequest['decision'];
    promise: Promise<AccordLockTaskAuthorizationDecisionAck>;
  } | null;
  revocation: Promise<AccordLockTaskAuthorizationRevokeAck> | null;
}

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

export type TrustedAuthorizedTaskContext = DeepReadonly<{
  windowId: number;
  objective: string;
  authorization: AccordLockTaskAuthorization;
  approvedSession: ApprovedSession;
}>;

export type TrustedTaskAuditBinding = DeepReadonly<{
  ledgerId: string;
  taskId: string;
  sessionId: string;
  runId: string;
  workspaceId: string;
  approvedAt: number;
  expiresAt: number;
  source: 'CURRENT_PROCESS' | 'DURABLE_INDEX';
}>;

type DurableTaskAuditIndex = Pick<AccordLockTaskAuditIndex, 'get' | 'record'>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function boundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    Buffer.byteLength(value, 'utf8') <= maximumBytes &&
    // Protocol text must exclude non-printable ASCII control bytes.
    // eslint-disable-next-line no-control-regex
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value)
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
  throw new Error('Task authorization contains a non-canonical JSON value');
}

export function accordLockDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

export function parseTaskRequest(value: unknown): AccordLockTaskRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['protocol', 'schema_version', 'session_id', 'objective']) ||
    value.protocol !== ACCORDLOCK_CONTROL_PROTOCOL ||
    value.schema_version !== 2 ||
    !boundedText(value.session_id, MAX_SESSION_ID_BYTES) ||
    !boundedText(value.objective, MAX_OBJECTIVE_BYTES)
  ) {
    throw new Error('Task request is malformed');
  }
  return value as unknown as AccordLockTaskRequest;
}

export function parseTaskAuthorizationRevokeRequest(
  value: unknown
): AccordLockTaskAuthorizationRevokeRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['protocol', 'schema_version', 'session_id']) ||
    value.protocol !== ACCORDLOCK_CONTROL_PROTOCOL ||
    value.schema_version !== 2 ||
    !boundedText(value.session_id, MAX_SESSION_ID_BYTES)
  ) {
    throw new Error('Task authorization revocation request is malformed');
  }
  return value as unknown as AccordLockTaskAuthorizationRevokeRequest;
}

export function parseTaskRestoreRequest(value: unknown): AccordLockTaskRestoreRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['protocol', 'schema_version', 'session_id', 'recovery_id']) ||
    value.protocol !== ACCORDLOCK_CONTROL_PROTOCOL ||
    value.schema_version !== 2 ||
    !boundedText(value.session_id, MAX_SESSION_ID_BYTES) ||
    typeof value.recovery_id !== 'string' ||
    value.recovery_id === '00000000-0000-0000-0000-000000000000' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.recovery_id)
  ) {
    throw new Error('File restore request is malformed');
  }
  return value as unknown as AccordLockTaskRestoreRequest;
}

export function parseTaskAuditRequest(value: unknown): AccordLockTaskAuditRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'protocol',
      'schema_version',
      'session_id',
      'offset',
      'limit',
      'snapshot_revision',
    ]) ||
    value.protocol !== ACCORDLOCK_CONTROL_PROTOCOL ||
    value.schema_version !== 2 ||
    !boundedText(value.session_id, MAX_SESSION_ID_BYTES) ||
    typeof value.offset !== 'number' ||
    !Number.isSafeInteger(value.offset) ||
    value.offset < 0 ||
    value.offset > 100_000 ||
    typeof value.limit !== 'number' ||
    !Number.isSafeInteger(value.limit) ||
    value.limit < 1 ||
    value.limit > 100 ||
    (value.snapshot_revision !== null &&
      (typeof value.snapshot_revision !== 'number' ||
        !Number.isSafeInteger(value.snapshot_revision) ||
        value.snapshot_revision < 0)) ||
    (value.offset === 0 && value.snapshot_revision !== null) ||
    (value.offset > 0 && value.snapshot_revision === null)
  ) {
    throw new Error('Task audit request is malformed');
  }
  return value as unknown as AccordLockTaskAuditRequest;
}

function parseTaskAuthorizationDecisionRequest(
  value: unknown
): AccordLockTaskAuthorizationDecisionRequest {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'protocol',
      'schema_version',
      'authorization_id',
      'task_id',
      'authorization_digest',
      'decision',
    ]) ||
    value.protocol !== ACCORDLOCK_CONTROL_PROTOCOL ||
    value.schema_version !== 2 ||
    typeof value.authorization_id !== 'string' ||
    typeof value.task_id !== 'string' ||
    typeof value.authorization_digest !== 'string' ||
    (value.decision !== 'APPROVE' && value.decision !== 'REJECT')
  ) {
    throw new Error('Task authorization decision request is malformed');
  }
  return value as unknown as AccordLockTaskAuthorizationDecisionRequest;
}

function exactDecisionBinding(
  request: AccordLockTaskAuthorizationDecisionRequest,
  record: TaskRecord
): boolean {
  return (
    request.authorization_id === record.authorization.authorization_id &&
    request.task_id === record.authorization.task_id &&
    (request.authorization_digest === record.authorization.authorization_digest ||
      request.authorization_digest === record.reviewedAuthorizationDigest)
  );
}

export class AccordLockTaskControl {
  private readonly recordsBySession = new Map<string, TaskRecord>();
  private readonly auditContextsBySession = new Map<string, TrustedAuthorizedTaskContext>();
  private readonly revocationByWindow = new Map<
    number,
    Promise<AccordLockTaskAuthorizationRevokeAck[]>
  >();
  private controlCommandTail: Promise<void> = Promise.resolve();
  private readonly ledgerId: string;

  constructor(
    private readonly durableAuditIndex: DurableTaskAuditIndex | null = null,
    ledgerId = randomUUID(),
    private readonly governedNetworkEnabled = false
  ) {
    if (!UUID.test(ledgerId)) {
      throw new Error('Runtime ledger identifier is invalid');
    }
    this.ledgerId = ledgerId;
  }

  private enqueueControlCommand<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.controlCommandTail.then(operation, operation);
    this.controlCommandTail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private recordForDecision(
    windowId: number,
    request: AccordLockTaskAuthorizationDecisionRequest
  ): TaskRecord {
    const record = [...this.recordsBySession.values()].find(
      (candidate) => candidate.authorization.authorization_id === request.authorization_id
    );
    if (!record || record.windowId !== windowId || !exactDecisionBinding(request, record)) {
      throw new Error('Task decision does not match a pending authorization');
    }
    if (record.revocation) {
      throw new Error('Task authorization is already being revoked');
    }
    return record;
  }

  private createRecord(
    windowId: number,
    request: AccordLockTaskRequest,
    workspaceRoot: string,
    trustedRunId: string,
    nowSeconds: number
  ): TaskRecord {
    const taskId = randomUUID();
    const taskPolicy: AccordLockTaskPolicy = {
      schema_version: 2,
      task_objective_hash: accordLockObjectiveDigest(request.objective),
      preauthorized_capabilities: AUTOMATIC_CAPABILITIES.map((capability) => ({ ...capability })),
      protected_paths: [...PROTECTED_PATHS],
    };
    const taskPolicyHash = accordLockTaskPolicyDigest(taskPolicy);
    const approvedSession: ApprovedSession = {
      schema_version: 3,
      task_id: taskId,
      session_id: request.session_id,
      run_id: trustedRunId,
      workspace_root: workspaceRoot,
      task_objective: request.objective,
      policy_epoch: 1,
      task_policy: taskPolicy,
      task_policy_hash: taskPolicyHash,
      capabilities: approvedCapabilities(this.governedNetworkEnabled),
      approved_at: nowSeconds,
      expires_at: nowSeconds + TASK_AUTHORIZATION_LIFETIME_SECONDS,
    };
    const authorization: AccordLockTaskAuthorization = {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      authorization_id: randomUUID(),
      task_id: taskId,
      session_id: request.session_id,
      authorization_digest: accordLockDigest(approvedSession),
      objective: request.objective,
      workspace_root: workspaceRoot,
      prepared_at: nowSeconds,
      expires_at: approvedSession.expires_at,
      task_policy: globalThis.structuredClone(taskPolicy),
      task_policy_hash: taskPolicyHash,
      capabilities: projectApprovedCapabilities(this.governedNetworkEnabled),
    };
    return {
      windowId,
      objective: request.objective,
      reviewedAuthorizationDigest: authorization.authorization_digest,
      authorization,
      approvedSession,
      decision: 'PENDING',
      acknowledgement: null,
      inFlight: null,
      revocation: null,
    };
  }

  configurePendingTaskAccess(
    windowId: number,
    rawRequest: unknown,
    selection: AccordLockTaskAccessSelection,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): AccordLockTaskAuthorizationDecisionRequest {
    const request = parseTaskAuthorizationDecisionRequest(rawRequest);
    if (request.decision !== 'APPROVE') {
      throw new Error('Only a pending approval can configure task access');
    }
    const record = this.recordForDecision(windowId, request);
    if (
      record.decision !== 'PENDING' ||
      record.acknowledgement ||
      record.inFlight ||
      nowSeconds >= record.authorization.expires_at
    ) {
      throw new Error('Task access can only change before approval');
    }
    if (
      !selection ||
      !['ASK', 'BLOCKED'].includes(selection.file_changes) ||
      !['ASK', 'BLOCKED'].includes(selection.terminal) ||
      !['ASK', 'BLOCKED'].includes(selection.network)
    ) {
      throw new Error('Task access selection is malformed');
    }
    if (selection.network === 'ASK' && !this.governedNetworkEnabled) {
      throw new Error('Controlled network access is not configured');
    }

    const capabilities = approvedCapabilities(
      this.governedNetworkEnabled && selection.network === 'ASK'
    ).filter((capability) => taskAccessAllows(selection, capability));
    const approvedSession: ApprovedSession = {
      ...record.approvedSession,
      capabilities,
    };
    const authorization: AccordLockTaskAuthorization = {
      ...record.authorization,
      authorization_digest: accordLockDigest(approvedSession),
      capabilities: projectApprovedCapabilities(
        this.governedNetworkEnabled && selection.network === 'ASK'
      ).filter((capability) => taskAccessAllows(selection, capability)),
    };
    record.approvedSession = approvedSession;
    record.authorization = authorization;

    return {
      ...request,
      authorization_digest: authorization.authorization_digest,
    };
  }

  private installFreshRecord(record: TaskRecord): AccordLockTaskAuthorization {
    // Delete before setting so a rotated task moves to the back of the
    // per-window authorization queue instead of jumping ahead of older tasks.
    this.recordsBySession.delete(record.authorization.session_id);
    this.auditContextsBySession.delete(record.authorization.session_id);
    this.recordsBySession.set(record.authorization.session_id, record);
    return record.authorization;
  }

  authorizationForDecision(
    windowId: number,
    rawRequest: unknown,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): {
    request: AccordLockTaskAuthorizationDecisionRequest;
    authorization: AccordLockTaskAuthorization;
    acknowledgement: AccordLockTaskAuthorizationDecisionAck | null;
  } {
    const request = parseTaskAuthorizationDecisionRequest(rawRequest);
    const record = this.recordForDecision(windowId, request);
    if (record.acknowledgement) {
      const expectedDecision = request.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
      if (record.decision !== expectedDecision) {
        throw new Error('Task already has a different recorded decision');
      }
    } else if (record.inFlight && record.inFlight.decision !== request.decision) {
      throw new Error('Task already has a different decision in flight');
    } else if (!record.inFlight && nowSeconds >= record.authorization.expires_at) {
      throw new Error('Task authorization expired before a decision was recorded');
    }
    return {
      request,
      authorization: globalThis.structuredClone(record.authorization),
      acknowledgement: record.acknowledgement
        ? globalThis.structuredClone(record.acknowledgement)
        : null,
    };
  }

  prepareTask(
    windowId: number,
    rawRequest: unknown,
    workspaceRoot: string,
    trustedRunId: string,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): AccordLockTaskAuthorization | null {
    const request = parseTaskRequest(rawRequest);
    if (this.revocationByWindow.has(windowId)) {
      throw new Error('Window task authorizations are being revoked');
    }
    if (!boundedText(workspaceRoot, MAX_WORKSPACE_BYTES)) {
      throw new Error('Trusted workspace binding is unavailable');
    }
    if (!SHA256_IDENTIFIER.test(trustedRunId)) {
      throw new Error('Trusted backend run binding is unavailable');
    }

    const existing = this.recordsBySession.get(request.session_id);
    if (existing) {
      if (existing.windowId !== windowId) {
        throw new Error('Session is already bound to a different task');
      }
      const expired =
        existing.decision === 'PENDING' && nowSeconds >= existing.authorization.expires_at;
      const canRotate = !existing.inFlight && (existing.decision === 'REJECTED' || expired);
      if (canRotate) {
        return this.installFreshRecord(
          this.createRecord(windowId, request, workspaceRoot, trustedRunId, nowSeconds)
        );
      }
      if (
        existing.objective !== request.objective ||
        existing.authorization.workspace_root !== workspaceRoot ||
        existing.approvedSession.run_id !== trustedRunId
      ) {
        throw new Error('Session is already bound to a different task');
      }
      if (expired) {
        throw new Error('Expired task authorization still has a decision in flight');
      }
      return existing.decision === 'PENDING' ? existing.authorization : null;
    }

    return this.installFreshRecord(
      this.createRecord(windowId, request, workspaceRoot, trustedRunId, nowSeconds)
    );
  }

  pendingAuthorizationsForWindow(
    windowId: number,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): AccordLockTaskAuthorization[] {
    const expiredRecords = [...this.recordsBySession.values()].filter(
      (record) =>
        record.windowId === windowId &&
        !record.revocation &&
        record.decision === 'PENDING' &&
        !record.inFlight &&
        nowSeconds >= record.authorization.expires_at
    );
    for (const record of expiredRecords) {
      if (this.recordsBySession.get(record.authorization.session_id) !== record) continue;
      this.installFreshRecord(
        this.createRecord(
          record.windowId,
          {
            protocol: ACCORDLOCK_CONTROL_PROTOCOL,
            schema_version: 2,
            session_id: record.authorization.session_id,
            objective: record.objective,
          },
          record.authorization.workspace_root,
          record.approvedSession.run_id,
          nowSeconds
        )
      );
    }

    const pending: AccordLockTaskAuthorization[] = [];
    for (const record of this.recordsBySession.values()) {
      if (
        record.windowId === windowId &&
        !record.revocation &&
        record.decision === 'PENDING' &&
        nowSeconds < record.authorization.expires_at
      ) {
        pending.push(record.authorization);
      }
    }
    return pending;
  }

  authorizedContextForSession(
    sessionId: string,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): TrustedAuthorizedTaskContext {
    if (!boundedText(sessionId, MAX_SESSION_ID_BYTES)) {
      throw new Error('Authorized task context is unavailable');
    }
    const record = this.recordsBySession.get(sessionId);
    if (
      !record ||
      record.decision !== 'APPROVED' ||
      record.acknowledgement?.status !== 'APPROVED' ||
      record.revocation ||
      nowSeconds >= record.approvedSession.expires_at
    ) {
      throw new Error('Authorized task context is unavailable');
    }
    return globalThis.structuredClone({
      windowId: record.windowId,
      objective: record.objective,
      authorization: record.authorization,
      approvedSession: record.approvedSession,
    });
  }

  auditContextForSession(sessionId: string): TrustedAuthorizedTaskContext {
    if (!boundedText(sessionId, MAX_SESSION_ID_BYTES)) {
      throw new Error('Task audit context is unavailable');
    }
    const context = this.auditContextsBySession.get(sessionId);
    if (!context) {
      throw new Error('Task audit context is unavailable');
    }
    return globalThis.structuredClone(context);
  }

  auditBindingForSession(
    windowId: number,
    sessionId: string,
    trustedWorkspaceId: string
  ): TrustedTaskAuditBinding {
    if (
      !Number.isSafeInteger(windowId) ||
      windowId <= 0 ||
      !boundedText(sessionId, MAX_SESSION_ID_BYTES) ||
      !SHA256_IDENTIFIER.test(trustedWorkspaceId)
    ) {
      throw new Error('Task audit binding is unavailable');
    }
    const current = this.auditContextsBySession.get(sessionId);
    if (current) {
      const currentWorkspaceId = accordLockAuditWorkspaceId(current.approvedSession.workspace_root);
      if (current.windowId !== windowId || currentWorkspaceId !== trustedWorkspaceId) {
        throw new Error('The task audit belongs to a different window');
      }
      return {
        ledgerId: this.ledgerId,
        taskId: current.approvedSession.task_id,
        sessionId: current.approvedSession.session_id,
        runId: current.approvedSession.run_id,
        workspaceId: currentWorkspaceId,
        approvedAt: current.approvedSession.approved_at,
        expiresAt: current.approvedSession.expires_at,
        source: 'CURRENT_PROCESS',
      };
    }

    const durable = this.durableAuditIndex?.get(sessionId);
    if (!durable) {
      throw new Error('Task audit binding is unavailable');
    }
    if (durable.workspace_id !== trustedWorkspaceId) {
      throw new Error('The task audit belongs to a different workspace');
    }
    return {
      ledgerId: durable.ledger_id,
      taskId: durable.task_id,
      sessionId: durable.session_id,
      runId: durable.run_id,
      workspaceId: durable.workspace_id,
      approvedAt: durable.approved_at,
      expiresAt: durable.expires_at,
      source: 'DURABLE_INDEX',
    };
  }

  private async performDecision(
    record: TaskRecord,
    decision: AccordLockTaskAuthorizationDecisionRequest['decision'],
    runtime: Pick<AccordLockRuntimeHandle, 'authorizeTask'>,
    nowSeconds: number
  ): Promise<AccordLockTaskAuthorizationDecisionAck> {
    let acknowledgement: AccordLockTaskAuthorizationDecisionAck;
    if (decision === 'APPROVE') {
      if (this.durableAuditIndex) {
        const durableEntry: AccordLockTaskAuditIndexEntry = {
          schema_version: 3,
          ledger_id: this.ledgerId,
          task_id: record.approvedSession.task_id,
          session_id: record.approvedSession.session_id,
          run_id: record.approvedSession.run_id,
          workspace_id: accordLockAuditWorkspaceId(record.approvedSession.workspace_root),
          approved_at: record.approvedSession.approved_at,
          expires_at: record.approvedSession.expires_at,
        };
        if (!(await this.durableAuditIndex.record(durableEntry))) {
          throw new Error('Protected task audit storage is unavailable');
        }
      }
      const runtimeAck = await this.enqueueControlCommand(() =>
        runtime.authorizeTask(record.approvedSession)
      );
      if (runtimeAck.approvalDigest !== record.authorization.authorization_digest) {
        throw new Error('Runtime acknowledged a different task authorization');
      }
      acknowledgement = {
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        authorization_id: record.authorization.authorization_id,
        task_id: record.authorization.task_id,
        reviewed_authorization_digest: record.reviewedAuthorizationDigest,
        authorization_digest: record.authorization.authorization_digest,
        status: 'APPROVED',
        reason_code: runtimeAck.code,
        reason:
          'The trusted runtime recorded the workspace, capabilities, and expiration time for this task.',
        decision_record: {
          record_id: runtimeAck.requestId,
          record_digest: runtimeAck.approvalDigest,
          recorded_at: nowSeconds,
        },
      };
      record.decision = 'APPROVED';
    } else {
      const recordId = randomUUID();
      const rejection = {
        schema_version: 2,
        record_id: recordId,
        authorization_id: record.authorization.authorization_id,
        task_id: record.authorization.task_id,
        authorization_digest: record.reviewedAuthorizationDigest,
        decision: 'REJECT',
        recorded_at: nowSeconds,
      };
      acknowledgement = {
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        authorization_id: record.authorization.authorization_id,
        task_id: record.authorization.task_id,
        reviewed_authorization_digest: record.reviewedAuthorizationDigest,
        authorization_digest: record.reviewedAuthorizationDigest,
        status: 'REJECTED',
        reason_code: 'TASK_AUTHORIZATION_REJECTED',
        reason: 'No task authorization was installed.',
        decision_record: {
          record_id: recordId,
          record_digest: accordLockDigest(rejection),
          recorded_at: nowSeconds,
        },
      };
      record.decision = 'REJECTED';
    }
    record.acknowledgement = acknowledgement;
    if (acknowledgement.status === 'APPROVED') {
      this.auditContextsBySession.delete(record.authorization.session_id);
      this.auditContextsBySession.set(
        record.authorization.session_id,
        globalThis.structuredClone({
          windowId: record.windowId,
          objective: record.objective,
          authorization: record.authorization,
          approvedSession: record.approvedSession,
        })
      );
      while (this.auditContextsBySession.size > 1_000) {
        const oldestSessionId = this.auditContextsBySession.keys().next().value;
        if (typeof oldestSessionId !== 'string') break;
        this.auditContextsBySession.delete(oldestSessionId);
      }
    }
    return acknowledgement;
  }

  async decideTaskAuthorization(
    windowId: number,
    rawRequest: unknown,
    runtime: Pick<AccordLockRuntimeHandle, 'authorizeTask'>,
    nowSeconds = Math.floor(Date.now() / 1_000)
  ): Promise<AccordLockTaskAuthorizationDecisionAck> {
    const request = parseTaskAuthorizationDecisionRequest(rawRequest);
    const record = this.recordForDecision(windowId, request);
    if (record.acknowledgement) {
      const expectedDecision = request.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
      if (record.decision !== expectedDecision) {
        throw new Error('Task already has a different recorded decision');
      }
      return record.acknowledgement;
    }
    if (record.inFlight) {
      if (record.inFlight.decision !== request.decision) {
        throw new Error('Task already has a different decision in flight');
      }
      return record.inFlight.promise;
    }
    if (nowSeconds >= record.authorization.expires_at) {
      throw new Error('Task authorization expired before a decision was recorded');
    }

    const operation = this.performDecision(record, request.decision, runtime, nowSeconds);
    record.inFlight = { decision: request.decision, promise: operation };
    try {
      return await operation;
    } finally {
      if (record.inFlight?.promise === operation) {
        record.inFlight = null;
      }
    }
  }

  private noAuthorizationRevocation(
    sessionId: string,
    record: TaskRecord | null,
    reasonCode: 'NO_SESSION_AUTHORIZATION' | 'NO_AUTHORIZATION_INSTALLED'
  ): AccordLockTaskAuthorizationRevokeAck {
    return {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      session_id: sessionId,
      task_id: record?.approvedSession.task_id ?? null,
      run_id: record?.approvedSession.run_id ?? null,
      status: 'REVOKED',
      reason_code: reasonCode,
      revocation_record: {
        request_id: null,
        revocation_digest: null,
      },
    };
  }

  private async performRevocation(
    record: TaskRecord,
    runtime: Pick<AccordLockRuntimeHandle, 'revokeSession'>
  ): Promise<AccordLockTaskAuthorizationRevokeAck> {
    // An APPROVE transport can be ambiguous until its promise settles. Treat it
    // as potentially authoritative so a failed response never skips revocation.
    let mayHaveAuthorization =
      record.decision === 'APPROVED' || record.inFlight?.decision === 'APPROVE';
    if (record.inFlight) {
      try {
        await record.inFlight.promise;
      } catch {
        // An ambiguous approval is resolved by attempting exact revocation below.
      }
      mayHaveAuthorization ||= record.decision === 'APPROVED';
    }

    let acknowledgement: AccordLockTaskAuthorizationRevokeAck;
    if (mayHaveAuthorization) {
      const revocation: SessionRevocation = {
        schema_version: 2,
        task_id: record.approvedSession.task_id,
        session_id: record.approvedSession.session_id,
        run_id: record.approvedSession.run_id,
      };
      const expectedDigest = accordLockDigest(revocation);
      const runtimeAck = await this.enqueueControlCommand(() => runtime.revokeSession(revocation));
      if (
        runtimeAck.revocationDigest !== expectedDigest ||
        runtimeAck.taskId !== revocation.task_id ||
        runtimeAck.sessionId !== revocation.session_id ||
        runtimeAck.runId !== revocation.run_id
      ) {
        throw new Error('Runtime acknowledged a different task authorization revocation');
      }
      acknowledgement = {
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        session_id: revocation.session_id,
        task_id: revocation.task_id,
        run_id: revocation.run_id,
        status: 'REVOKED',
        reason_code:
          runtimeAck.code === 'SESSION_ALREADY_REVOKED'
            ? 'TASK_AUTHORIZATION_ALREADY_REVOKED'
            : 'TASK_AUTHORIZATION_REVOKED',
        revocation_record: {
          request_id: runtimeAck.requestId,
          revocation_digest: runtimeAck.revocationDigest,
        },
      };
    } else {
      acknowledgement = this.noAuthorizationRevocation(
        record.authorization.session_id,
        record,
        'NO_AUTHORIZATION_INSTALLED'
      );
    }

    if (this.recordsBySession.get(record.authorization.session_id) === record) {
      this.recordsBySession.delete(record.authorization.session_id);
    }
    return acknowledgement;
  }

  async revokeSessionAuthorization(
    windowId: number,
    rawRequest: unknown,
    runtime: Pick<AccordLockRuntimeHandle, 'revokeSession'>
  ): Promise<AccordLockTaskAuthorizationRevokeAck> {
    const request = parseTaskAuthorizationRevokeRequest(rawRequest);
    const record = this.recordsBySession.get(request.session_id);
    if (!record) {
      return this.noAuthorizationRevocation(request.session_id, null, 'NO_SESSION_AUTHORIZATION');
    }
    if (record.windowId !== windowId) {
      throw new Error('Task authorization revocation does not belong to this window');
    }
    if (record.revocation) {
      return record.revocation;
    }

    const operation = this.performRevocation(record, runtime);
    record.revocation = operation;
    try {
      return await operation;
    } finally {
      if (record.revocation === operation) {
        record.revocation = null;
      }
    }
  }

  async revokeWindowAuthorizations(
    windowId: number,
    runtime: Pick<AccordLockRuntimeHandle, 'revokeSession'>
  ): Promise<AccordLockTaskAuthorizationRevokeAck[]> {
    const existing = this.revocationByWindow.get(windowId);
    if (existing) {
      return existing;
    }

    // Defer the snapshot by one microtask so the window block is installed
    // before revocation work can yield to another renderer request.
    const operation = Promise.resolve().then(async () => {
      const sessionIds = [...this.recordsBySession.values()]
        .filter((record) => record.windowId === windowId)
        .map((record) => record.authorization.session_id);
      const acknowledgements: AccordLockTaskAuthorizationRevokeAck[] = [];
      for (const sessionId of sessionIds) {
        acknowledgements.push(
          await this.revokeSessionAuthorization(
            windowId,
            {
              protocol: ACCORDLOCK_CONTROL_PROTOCOL,
              schema_version: 2,
              session_id: sessionId,
            },
            runtime
          )
        );
      }
      return acknowledgements;
    });
    this.revocationByWindow.set(windowId, operation);
    try {
      return await operation;
    } finally {
      if (this.revocationByWindow.get(windowId) === operation) {
        this.revocationByWindow.delete(windowId);
      }
    }
  }
}

/** Revoke every task authorization before reloading its renderer window. */
export async function revokeBeforeAccordLockWindowReload(
  windowId: number,
  reloadWindow: () => void | Promise<void>,
  control: Pick<AccordLockTaskControl, 'revokeWindowAuthorizations'>,
  runtime: Parameters<AccordLockTaskControl['revokeWindowAuthorizations']>[1]
): Promise<void> {
  await revokeAccordLockWindowAuthorizations(windowId, control, runtime);
  await reloadWindow();
}

export function interceptUnexpectedAccordLockTopLevelNavigation(
  event: Pick<Event, 'preventDefault'>,
  revokeAndReload: () => void
): void {
  event.preventDefault();
  revokeAndReload();
}

/** Removes every task authorization owned by a renderer window. */
export async function revokeAccordLockWindowAuthorizations(
  windowId: number,
  control: Pick<AccordLockTaskControl, 'revokeWindowAuthorizations'>,
  runtime: Parameters<AccordLockTaskControl['revokeWindowAuthorizations']>[1]
): Promise<void> {
  await control.revokeWindowAuthorizations(windowId, runtime);
}
