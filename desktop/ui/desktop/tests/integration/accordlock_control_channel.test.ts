import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  ACCORDLOCK_RUNTIME_MARKER_FILENAME,
  accordLockObjectiveDigest,
  accordLockRuntimeBinaryName,
  accordLockTaskPolicyDigest,
  startAccordLockRuntime,
  type AccordLockRuntimeHandle,
  type ApprovedSession,
  type SessionRevocation,
} from '../../src/accordlockRuntime';
import {
  bindAccordLockActionApproval,
  parseAccordLockActionApprovalChallenge,
} from '../../src/accordlockActionApproval';
import { startAccordLockApprovalProxy } from '../../src/accordlockApprovalProxy';

type RuntimeKillSignal = Parameters<AccordLockRuntimeHandle['process']['kill']>[0];

// This smoke never invokes Cargo. CI can provide a verified prebuilt path;
// local development falls back to the sibling AccordLock debug artifact.
const configuredBinary = process.env.ACCORDLOCK_TEST_RUNTIME_BINARY;
const defaultBinary = path.resolve(
  process.cwd(),
  '..',
  '..',
  '..',
  '..',
  '..',
  'accordlock',
  'target',
  'debug',
  accordLockRuntimeBinaryName()
);
const runtimeBinary = path.resolve(configuredBinary ?? defaultBinary);

const existingRegularFile = (filePath: string): boolean => {
  try {
    const metadata = fs.lstatSync(filePath);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch {
    return false;
  }
};

const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`;
  }
  throw new Error('integration fixture is not canonical JSON');
};

const digest = (value: unknown): string =>
  `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;

const rustCanonicalWorkspace = (directory: string): string => {
  const real = fs.realpathSync.native(directory);
  if (process.platform !== 'win32' || real.startsWith('\\\\?\\')) {
    return real;
  }
  return `\\\\?\\${real}`;
};

describe('AccordLock Desktop ↔ Rust ControlChannel', () => {
  let testRoot = '';
  let binDirectory = '';
  let dataDirectory = '';
  let workspaceDirectory = '';

  beforeAll(() => {
    if (!existingRegularFile(runtimeBinary)) {
      return;
    }
    testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-cross-process-'));
    binDirectory = path.join(testRoot, 'bin');
    dataDirectory = path.join(testRoot, 'data');
    workspaceDirectory = path.join(testRoot, 'workspace');
    fs.mkdirSync(binDirectory);
    fs.mkdirSync(dataDirectory);
    fs.mkdirSync(workspaceDirectory);

    const binaryName = accordLockRuntimeBinaryName();
    const stagedBinary = path.join(binDirectory, binaryName);
    fs.copyFileSync(runtimeBinary, stagedBinary);
    if (process.platform !== 'win32') {
      fs.chmodSync(stagedBinary, 0o755);
    }
    const binarySha256 = createHash('sha256').update(fs.readFileSync(stagedBinary)).digest('hex');
    fs.writeFileSync(
      path.join(binDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      JSON.stringify({
        schema_version: 2,
        distribution: 'AccordLock',
        component: 'accordlock-agent-runtime',
        protocol_version: 2,
        source_commit: 'f'.repeat(40),
        source_dirty: false,
        binary: binaryName,
        binary_sha256: binarySha256,
      })
    );
  });

  afterAll(() => {
    if (testRoot) {
      fs.rmSync(testRoot, { recursive: true, force: true });
    }
  });

  if (!existingRegularFile(runtimeBinary)) {
    it.skip(`requires ACCORDLOCK_TEST_RUNTIME_BINARY or prebuilt default binary (${runtimeBinary})`, () => {});
    return;
  }

  it('approves then revokes one session, blocks future authority, and exits on stdin EOF', async () => {
    let runtime: AccordLockRuntimeHandle | null = null;
    try {
      runtime = await startAccordLockRuntime({
        binDirectory,
        dataDirectory,
        logger: { info: () => {}, error: () => {} },
        startupTimeoutMs: 10_000,
        controlRequestTimeoutMs: 5_000,
        shutdownTimeoutMs: 5_000,
      });
      expect(runtime.runtimeUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/u);

      const now = Math.floor(Date.now() / 1_000);
      const sessionId = `cross-process-${randomUUID()}`;
      const taskPolicy = {
        schema_version: 2 as const,
        task_objective_hash: accordLockObjectiveDigest('cross-process control proof'),
        preauthorized_capabilities: [],
        protected_paths: ['.accordlock'],
      };
      const approvedSession: ApprovedSession = {
        schema_version: 3,
        task_id: randomUUID(),
        session_id: sessionId,
        run_id: sessionId,
        workspace_root: rustCanonicalWorkspace(workspaceDirectory),
        task_objective: 'cross-process control proof',
        policy_epoch: 1,
        task_policy: taskPolicy,
        task_policy_hash: accordLockTaskPolicyDigest(taskPolicy),
        capabilities: [{ extension_id: 'developer', tool_name: 'write' }],
        approved_at: now - 1,
        expires_at: now + 300,
      };

      const acknowledgement = await runtime.authorizeTask(approvedSession);
      expect(acknowledgement.code).toBe('SESSION_APPROVED');
      expect(acknowledgement.approvalDigest).toBe(digest(approvedSession));
      expect(acknowledgement.requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
      );

      const revocation: SessionRevocation = {
        schema_version: 2,
        task_id: approvedSession.task_id,
        session_id: approvedSession.session_id,
        run_id: approvedSession.run_id,
      };
      const revocationReceipt = await runtime.revokeSession(revocation);
      expect(revocationReceipt.code).toBe('SESSION_REVOKED');
      expect(revocationReceipt.revocationDigest).toBe(digest(revocation));
      expect(revocationReceipt).toMatchObject({
        taskId: approvedSession.task_id,
        sessionId: approvedSession.session_id,
        runId: approvedSession.run_id,
      });

      const argumentsValue = { content: 'must not execute', path: 'revoked.txt' };
      const argumentsSha256 = digest(argumentsValue);
      const toolCallId = `revoked-${randomUUID()}`;
      const planMaterial = {
        text: ['Execute the exact test action.'],
        tool_requests: [
          { id: toolCallId, name: 'developer__write', arguments_sha256: argumentsSha256 },
        ],
      };
      const executionBody = Buffer.from(
        JSON.stringify({
          schema_version: 3,
          proposal: {
            schema_version: 3,
            session_id: approvedSession.session_id,
            run_id: approvedSession.run_id,
            tool_call_id: toolCallId,
            workspace_root: approvedSession.workspace_root,
            extension_id: 'developer',
            tool_name: 'write',
            arguments: argumentsValue,
            arguments_sha256: argumentsSha256,
            agent_plan_checkpoint: {
              schema_version: 1,
              session_id: approvedSession.session_id,
              run_id: approvedSession.run_id,
              tool_call_id: toolCallId,
              material: planMaterial,
              material_sha256: digest(planMaterial),
              recorded_at: now,
            },
          },
        }),
        'utf8'
      );
      const execution = await runtime.forwardPolicyRequest(
        '/api/v2/execution/filesystem/authorize-and-execute',
        'POST',
        executionBody
      );
      expect(execution.status).toBe(200);
      expect(JSON.parse(Buffer.from(execution.body).toString('utf8'))).toMatchObject({
        schema_version: 3,
        status: 'DENIED',
        reason_code: 'SESSION_REVOKED',
      });

      const observedSignals: RuntimeKillSignal[] = [];
      const originalKill = runtime.process.kill.bind(runtime.process);
      runtime.process.kill = ((signal?: RuntimeKillSignal) => {
        observedSignals.push(signal);
        return originalKill(signal);
      }) as typeof runtime.process.kill;

      await runtime.cleanup();
      expect(observedSignals).toEqual([]);
      expect(runtime.hasExited()).toBe(true);
      expect(runtime.getExitDetails()).toEqual({ code: 0, signal: null });
      expect(fs.existsSync(path.join(dataDirectory, 'agent-runtime.sqlite3'))).toBe(true);
    } finally {
      await runtime?.cleanup();
    }
  }, 30_000);

  it('approves one exact write through the proxy, records a denial, and rejects stale state', async () => {
    let runtime: AccordLockRuntimeHandle | null = null;
    let approvalProxy: Awaited<ReturnType<typeof startAccordLockApprovalProxy>> | null = null;
    try {
      runtime = await startAccordLockRuntime({
        binDirectory,
        dataDirectory,
        logger: { info: () => {}, error: () => {} },
        startupTimeoutMs: 10_000,
        controlRequestTimeoutMs: 5_000,
        shutdownTimeoutMs: 5_000,
      });
      const now = Math.floor(Date.now() / 1_000);
      const sessionId = `policy-proxy-${randomUUID()}`;
      const taskPolicy = {
        schema_version: 2 as const,
        task_objective_hash: accordLockObjectiveDigest('write one approved file'),
        preauthorized_capabilities: [
          { extension_id: 'developer', tool_name: 'read' },
          { extension_id: 'developer', tool_name: 'tree' },
        ],
        protected_paths: ['.accordlock', '.env', '.git'],
      };
      const approvedSession: ApprovedSession = {
        schema_version: 3,
        task_id: randomUUID(),
        session_id: sessionId,
        run_id: `run-${randomUUID()}`,
        workspace_root: rustCanonicalWorkspace(workspaceDirectory),
        task_objective: 'write one approved file',
        policy_epoch: 1,
        task_policy: taskPolicy,
        task_policy_hash: accordLockTaskPolicyDigest(taskPolicy),
        capabilities: [
          { extension_id: 'developer', tool_name: 'edit' },
          { extension_id: 'developer', tool_name: 'read' },
          { extension_id: 'developer', tool_name: 'tree' },
          { extension_id: 'developer', tool_name: 'write' },
        ],
        approved_at: now - 1,
        expires_at: now + 300,
      };
      await runtime.authorizeTask(approvedSession);

      let approvalCount = 0;
      approvalProxy = await startAccordLockApprovalProxy({
        forward: (requestPath, method, body) =>
          runtime!.forwardPolicyRequest(requestPath, method, body),
        resolveApproval: async (request) => {
          approvalCount += 1;
          const challenge = parseAccordLockActionApprovalChallenge(request);
          const outcome =
            challenge.approvalRequest.action.relative_path === 'denied.txt' ? 'DENIED' : 'APPROVED';
          if (challenge.approvalRequest.action.relative_path === 'race.txt') {
            fs.writeFileSync(path.join(workspaceDirectory, 'race.txt'), 'external state');
          }
          const decidedAt = Math.floor(Date.now() / 1_000);
          const approval = bindAccordLockActionApproval(
            challenge,
            approvedSession,
            outcome,
            randomUUID(),
            decidedAt
          );
          await runtime!.registerActionApproval(approval);
          return true;
        },
      });

      const executeWrite = async (relativePath: string, content: string) => {
        const argumentsValue = { path: relativePath, content };
        const argumentsSha256 = digest(argumentsValue);
        const toolCallId = `write-${relativePath}-${randomUUID()}`;
        const planMaterial = {
          text: ['Execute the exact test action.'],
          tool_requests: [
            { id: toolCallId, name: 'developer__write', arguments_sha256: argumentsSha256 },
          ],
        };
        const proposal = {
          schema_version: 3,
          session_id: approvedSession.session_id,
          run_id: approvedSession.run_id,
          tool_call_id: toolCallId,
          workspace_root: approvedSession.workspace_root,
          extension_id: 'developer',
          tool_name: 'write',
          arguments: argumentsValue,
          arguments_sha256: argumentsSha256,
          agent_plan_checkpoint: {
            schema_version: 1,
            session_id: approvedSession.session_id,
            run_id: approvedSession.run_id,
            tool_call_id: toolCallId,
            material: planMaterial,
            material_sha256: digest(planMaterial),
            recorded_at: now,
          },
        };
        const response = await fetch(
          `${approvalProxy!.baseUrl}/api/v2/execution/filesystem/authorize-and-execute`,
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${approvalProxy!.bearer}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ schema_version: 3, proposal }),
          }
        );
        expect(response.status).toBe(200);
        return (await response.json()) as Record<string, unknown>;
      };

      const allowed = await executeWrite('allowed.txt', 'authorized content');
      expect(allowed).toMatchObject({ status: 'SUCCEEDED', reason_code: 'EXECUTED' });
      expect(fs.readFileSync(path.join(workspaceDirectory, 'allowed.txt'), 'utf8')).toBe(
        'authorized content'
      );

      const denied = await executeWrite('denied.txt', 'must not exist');
      expect(denied).toMatchObject({
        status: 'DENIED',
        reason_code: 'ACTION_APPROVAL_DENIED',
      });
      expect(fs.existsSync(path.join(workspaceDirectory, 'denied.txt'))).toBe(false);

      const stale = await executeWrite('race.txt', 'must not replace external state');
      expect(stale).toMatchObject({
        status: 'DENIED',
        reason_code: 'ACTION_APPROVAL_SCOPE_MISMATCH',
      });
      expect(fs.readFileSync(path.join(workspaceDirectory, 'race.txt'), 'utf8')).toBe(
        'external state'
      );
      expect(approvalCount).toBe(3);
    } finally {
      await approvalProxy?.cleanup();
      await runtime?.cleanup();
    }
  }, 30_000);
});
