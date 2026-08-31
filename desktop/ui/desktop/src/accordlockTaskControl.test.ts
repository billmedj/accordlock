import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  ACCORDLOCK_CONTROL_PROTOCOL,
  type AccordLockTaskAuthorizationDecisionRequest,
} from './accordlock/taskIpc';
import {
  AccordLockTaskControl,
  accordLockDigest,
  interceptUnexpectedAccordLockTopLevelNavigation,
  parseTaskAuditRequest,
  parseTaskRestoreRequest,
  revokeAccordLockWindowAuthorizations,
  revokeBeforeAccordLockWindowReload,
  type ApprovedSession,
} from './accordlockTaskControl';

import type { SessionRevocation } from './accordlockRuntime';
import { deriveAccordLockBackendRunId } from './accordlockBackendBinding';
import {
  accordLockAuditWorkspaceId,
  type AccordLockTaskAuditIndexEntry,
} from './accordlockTaskAuditIndex';

const LEDGER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const RESTARTED_LEDGER_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ZERO_BINDING_SECRET = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const trustedRunId = (sessionId: string): string =>
  deriveAccordLockBackendRunId(ZERO_BINDING_SECRET, sessionId);

const request = {
  protocol: ACCORDLOCK_CONTROL_PROTOCOL,
  schema_version: 2 as const,
  session_id: 'session-1',
  objective: 'Update the release notes without leaving this workspace.',
};

function decision(
  authorization: ReturnType<AccordLockTaskControl['prepareTask']>,
  value: 'APPROVE' | 'REJECT'
): AccordLockTaskAuthorizationDecisionRequest {
  if (!authorization) throw new Error('expected authorization');
  return {
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    authorization_id: authorization.authorization_id,
    task_id: authorization.task_id,
    authorization_digest: authorization.authorization_digest,
    decision: value,
  };
}

function runtime() {
  return {
    authorizeTask: vi.fn(async (approvedSession: ApprovedSession) => ({
      requestId: '11111111-1111-4111-8111-111111111111',
      code: 'SESSION_APPROVED' as const,
      approvalDigest: accordLockDigest(approvedSession),
    })),
  };
}

function deferredRuntime() {
  let complete: (() => void) | undefined;
  const authorizeTask = vi.fn(
    (approvedSession: ApprovedSession) =>
      new Promise<{
        requestId: string;
        code: 'SESSION_APPROVED';
        approvalDigest: string;
      }>((resolve) => {
        complete = () =>
          resolve({
            requestId: '11111111-1111-4111-8111-111111111111',
            code: 'SESSION_APPROVED',
            approvalDigest: accordLockDigest(approvedSession),
          });
      })
  );
  return {
    trustedRuntime: { authorizeTask },
    complete: () => {
      if (!complete) throw new Error('authorization was not started');
      complete();
    },
  };
}

function revocationRuntime() {
  return {
    revokeSession: vi.fn(async (revocation: SessionRevocation) => ({
      requestId: '22222222-2222-4222-8222-222222222222',
      code: 'SESSION_REVOKED' as const,
      revocationDigest: accordLockDigest(revocation),
      taskId: revocation.task_id,
      sessionId: revocation.session_id,
      runId: revocation.run_id,
    })),
  };
}

const revocationRequest = (sessionId = request.session_id) => ({
  protocol: ACCORDLOCK_CONTROL_PROTOCOL,
  schema_version: 2 as const,
  session_id: sessionId,
});

describe('AccordLockTaskControl', () => {
  it('accepts only a bounded exact audit request', () => {
    const auditRequest = {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      session_id: 'session-1',
      offset: 0,
      limit: 100,
      snapshot_revision: null,
    };
    expect(parseTaskAuditRequest(auditRequest)).toEqual(auditRequest);
    expect(() => parseTaskAuditRequest({ ...auditRequest, include_arguments: true })).toThrow(
      'malformed'
    );
    expect(() => parseTaskAuditRequest({ ...auditRequest, limit: 101 })).toThrow('malformed');
    expect(() => parseTaskAuditRequest({ ...auditRequest, offset: -1 })).toThrow('malformed');
    expect(() =>
      parseTaskAuditRequest({ ...auditRequest, offset: 1, snapshot_revision: null })
    ).toThrow('malformed');
    expect(() =>
      parseTaskAuditRequest({ ...auditRequest, offset: 1, snapshot_revision: 7 })
    ).not.toThrow();
  });

  it('accepts only an opaque canonical recovery identifier from the renderer', () => {
    const recoveryRequest = {
      protocol: ACCORDLOCK_CONTROL_PROTOCOL,
      schema_version: 2,
      session_id: 'session-1',
      recovery_id: 'a8888888-8888-4888-8888-888888888888',
    };

    expect(parseTaskRestoreRequest(recoveryRequest)).toEqual(recoveryRequest);
    expect(() =>
      parseTaskRestoreRequest({ ...recoveryRequest, relative_path: 'secret.txt' })
    ).toThrow('malformed');
    expect(() =>
      parseTaskRestoreRequest({
        ...recoveryRequest,
        recovery_id: '00000000-0000-0000-0000-000000000000',
      })
    ).toThrow('malformed');
    expect(() =>
      parseTaskRestoreRequest({
        ...recoveryRequest,
        recovery_id: recoveryRequest.recovery_id.toUpperCase(),
      })
    ).toThrow('malformed');
  });

  it('prepares one deterministic authority projection per exact session binding', () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const retry = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_001
    );

    expect(authorization).not.toBeNull();
    expect(retry).toEqual(authorization);
    expect(authorization?.session_id).toBe(request.session_id);
    expect(authorization?.workspace_root).toBe('/trusted/workspace');
    expect(authorization?.expires_at).toBe(1_000 + 8 * 60 * 60);
    expect(
      authorization?.capabilities.map(
        ({ extension_id, tool_name }) => `${extension_id}/${tool_name}`
      )
    ).toEqual([
      'developer/read',
      'developer/tree',
      'developer/edit',
      'developer/write',
      'developer/delete_file',
      'developer/shell',
    ]);
    expect(authorization?.capabilities[5]).toMatchObject({
      extension_id: 'developer',
      tool_name: 'shell',
      operation_type: 'EXECUTE',
      display_name: 'Run approved programs',
    });
    expect(control.pendingAuthorizationsForWindow(7, 1_001)).toEqual([authorization]);
    expect(() =>
      control.prepareTask(
        7,
        { ...request, objective: 'Different task' },
        '/trusted/workspace',
        trustedRunId(request.session_id),
        1_002
      )
    ).toThrow('different task');
  });

  it('projects controlled HTTPS only when the trusted startup policy enabled it', async () => {
    const control = new AccordLockTaskControl(null, LEDGER_ID, true);
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );

    expect(authorization?.capabilities[0]).toMatchObject({
      extension_id: 'accordlock_network',
      tool_name: 'https_request',
      operation_type: 'NETWORK',
      display_name: 'Read approved websites',
    });
    expect(authorization?.task_policy.preauthorized_capabilities).not.toContainEqual({
      extension_id: 'accordlock_network',
      tool_name: 'https_request',
    });

    const trustedRuntime = runtime();
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );
    const installed = trustedRuntime.authorizeTask.mock.calls[0]?.[0];
    expect(installed?.capabilities[0]).toEqual({
      extension_id: 'accordlock_network',
      tool_name: 'https_request',
    });
    expect(installed?.task_policy.preauthorized_capabilities).not.toContainEqual({
      extension_id: 'accordlock_network',
      tool_name: 'https_request',
    });
  });

  it('keeps the window-bound audit identity available after revocation', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    await control.decideTaskAuthorization(7, decision(authorization, 'APPROVE'), runtime(), 1_001);
    await control.revokeSessionAuthorization(7, revocationRequest(), revocationRuntime());

    expect(control.auditContextForSession(request.session_id)).toMatchObject({
      windowId: 7,
      approvedSession: { session_id: request.session_id },
    });
    expect(() => control.auditContextForSession('session-2')).toThrow('unavailable');
  });

  it('persists only the redacted audit binding and rebinds it to one trusted window after restart', async () => {
    const durableEntries = new Map<string, AccordLockTaskAuditIndexEntry>();
    const durableIndex = {
      get: vi.fn((sessionId: string) => durableEntries.get(sessionId) ?? null),
      record: vi.fn(async (binding: AccordLockTaskAuditIndexEntry) => {
        durableEntries.set(binding.session_id, globalThis.structuredClone(binding));
        return true;
      }),
    };
    const firstProcess = new AccordLockTaskControl(durableIndex, LEDGER_ID);
    const authorization = firstProcess.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = runtime();
    await firstProcess.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    expect(durableIndex.record).toHaveBeenCalledWith({
      schema_version: 3,
      ledger_id: LEDGER_ID,
      task_id: authorization?.task_id,
      session_id: request.session_id,
      run_id: trustedRunId(request.session_id),
      workspace_id: accordLockAuditWorkspaceId('/trusted/workspace'),
      approved_at: 1_000,
      expires_at: 1_000 + 8 * 60 * 60,
    });
    expect(JSON.stringify(durableIndex.record.mock.calls)).not.toContain(request.objective);
    expect(JSON.stringify(durableIndex.record.mock.calls)).not.toContain('/trusted/workspace');
    expect(durableIndex.record.mock.invocationCallOrder[0]).toBeLessThan(
      trustedRuntime.authorizeTask.mock.invocationCallOrder[0]
    );

    const restarted = new AccordLockTaskControl(durableIndex, RESTARTED_LEDGER_ID);
    const workspaceId = accordLockAuditWorkspaceId('/trusted/workspace');
    expect(restarted.auditBindingForSession(12, request.session_id, workspaceId)).toMatchObject({
      taskId: authorization?.task_id,
      sessionId: request.session_id,
      runId: trustedRunId(request.session_id),
      ledgerId: LEDGER_ID,
      workspaceId,
      source: 'DURABLE_INDEX',
    });
    expect(() =>
      restarted.auditBindingForSession(
        13,
        request.session_id,
        accordLockAuditWorkspaceId('/other/workspace')
      )
    ).toThrow('different workspace');
    expect(restarted.auditBindingForSession(13, request.session_id, workspaceId).source).toBe(
      'DURABLE_INDEX'
    );
  });

  it('does not install runtime authority when durable audit storage is unavailable', async () => {
    const durableIndex = {
      get: vi.fn(() => null),
      record: vi.fn(async () => false),
    };
    const control = new AccordLockTaskControl(durableIndex);
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = runtime();

    await expect(
      control.decideTaskAuthorization(7, decision(authorization, 'APPROVE'), trustedRuntime, 1_001)
    ).rejects.toThrow('audit storage is unavailable');
    expect(trustedRuntime.authorizeTask).not.toHaveBeenCalled();
  });

  it('never lets a durable historical binding override a current window binding', async () => {
    const durableIndex = {
      get: vi.fn(() => ({
        schema_version: 3 as const,
        ledger_id: LEDGER_ID,
        task_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        session_id: request.session_id,
        run_id: `sha256:${'9'.repeat(64)}`,
        workspace_id: accordLockAuditWorkspaceId('/other/workspace'),
        approved_at: 1,
        expires_at: 2,
      })),
      record: vi.fn(async () => true),
    };
    const control = new AccordLockTaskControl(durableIndex);
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    await control.decideTaskAuthorization(7, decision(authorization, 'APPROVE'), runtime(), 1_001);

    expect(
      control.auditBindingForSession(
        7,
        request.session_id,
        accordLockAuditWorkspaceId('/trusted/workspace')
      )
    ).toMatchObject({
      taskId: authorization?.task_id,
      runId: trustedRunId(request.session_id),
      source: 'CURRENT_PROCESS',
    });
    expect(durableIndex.get).not.toHaveBeenCalled();
    expect(() =>
      control.auditBindingForSession(
        8,
        request.session_id,
        accordLockAuditWorkspaceId('/trusted/workspace')
      )
    ).toThrow('different window');
    expect(() =>
      control.auditBindingForSession(
        7,
        request.session_id,
        accordLockAuditWorkspaceId('/other/workspace')
      )
    ).toThrow('different window');
  });

  it('requires one trusted cryptographic run binding and never substitutes the session id', () => {
    const control = new AccordLockTaskControl();
    expect(() =>
      control.prepareTask(7, request, '/trusted/workspace', request.session_id, 1_000)
    ).toThrow('Trusted backend run binding is unavailable');

    control.prepareTask(7, request, '/trusted/workspace', trustedRunId(request.session_id), 1_000);
    const otherBackendRunId = deriveAccordLockBackendRunId(
      Buffer.alloc(32, 1).toString('base64url'),
      request.session_id
    );
    expect(() =>
      control.prepareTask(7, request, '/trusted/workspace', otherBackendRunId, 1_001)
    ).toThrow('different task');
  });

  it('installs only the authorized policy and returns the runtime decision record', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = runtime();

    const acknowledgement = await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    expect(acknowledgement.status).toBe('APPROVED');
    expect(acknowledgement.authorization_digest).toBe(authorization?.authorization_digest);
    expect(acknowledgement.decision_record.record_id).toBe('11111111-1111-4111-8111-111111111111');
    expect(trustedRuntime.authorizeTask).toHaveBeenCalledOnce();
    expect(control.pendingAuthorizationsForWindow(7, 1_001)).toEqual([]);
    const installedSession = trustedRuntime.authorizeTask.mock.calls[0][0];
    expect(installedSession.schema_version).toBe(3);
    expect(installedSession.task_objective).toBe(request.objective);
    expect(installedSession.run_id).toBe(trustedRunId(request.session_id));
    expect(installedSession.capabilities).toEqual([
      { extension_id: 'developer', tool_name: 'delete_file' },
      { extension_id: 'developer', tool_name: 'edit' },
      { extension_id: 'developer', tool_name: 'read' },
      { extension_id: 'developer', tool_name: 'shell' },
      { extension_id: 'developer', tool_name: 'tree' },
      { extension_id: 'developer', tool_name: 'write' },
    ]);
    expect(installedSession.task_policy).toEqual({
      schema_version: 2,
      task_objective_hash: `sha256:${createHash('sha256')
        .update(request.objective, 'utf8')
        .digest('hex')}`,
      preauthorized_capabilities: [
        { extension_id: 'developer', tool_name: 'read' },
        { extension_id: 'developer', tool_name: 'tree' },
      ],
      protected_paths: [
        '.accordlock',
        '.env',
        '.git',
        '.goose',
        '.goosehints',
        '.ssh',
        'credentials',
      ],
    });
    expect(installedSession.task_policy_hash).not.toBe(
      accordLockDigest(installedSession.task_policy)
    );

    const retry = await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_002
    );
    expect(retry).toEqual(acknowledgement);
    expect(trustedRuntime.authorizeTask).toHaveBeenCalledOnce();
  });

  it('returns an isolated trusted context only while exact authority is approved and current', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );

    expect(() => control.authorizedContextForSession(request.session_id, 1_000)).toThrow(
      'unavailable'
    );
    await control.decideTaskAuthorization(7, decision(authorization, 'APPROVE'), runtime(), 1_001);

    const first = control.authorizedContextForSession(request.session_id, 1_002);
    expect(first).toMatchObject({
      windowId: 7,
      objective: request.objective,
      authorization: { task_id: authorization?.task_id },
      approvedSession: { session_id: request.session_id },
    });
    (first.authorization as { objective: string }).objective = 'mutated copy';
    (
      first.approvedSession.capabilities as unknown as {
        tool_name: string;
      }[]
    )[0].tool_name = 'mutated-copy';

    const second = control.authorizedContextForSession(request.session_id, 1_003);
    expect(second.authorization.objective).toBe(request.objective);
    expect(second.approvedSession.capabilities[0].tool_name).toBe('delete_file');
    expect(() =>
      control.authorizedContextForSession(request.session_id, 1_000 + 8 * 60 * 60)
    ).toThrow('unavailable');
    expect(() => control.authorizedContextForSession(' unknown ', 1_003)).toThrow('unavailable');
  });

  it('serializes a decision with one in-flight operation and one terminal outcome', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const { trustedRuntime, complete } = deferredRuntime();

    const firstApproval = control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );
    const exactRetry = control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );
    await expect(
      control.decideTaskAuthorization(7, decision(authorization, 'REJECT'), trustedRuntime, 1_001)
    ).rejects.toThrow('different decision in flight');

    expect(trustedRuntime.authorizeTask).toHaveBeenCalledOnce();
    complete();
    const [first, retry] = await Promise.all([firstApproval, exactRetry]);
    expect(first.status).toBe('APPROVED');
    expect(retry).toEqual(first);
    await expect(
      control.decideTaskAuthorization(7, decision(authorization, 'REJECT'), trustedRuntime, 1_002)
    ).rejects.toThrow('different recorded decision');
  });

  it('rotates expired and rejected task authorizations without accepting stale decisions', async () => {
    const control = new AccordLockTaskControl();
    const first = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const expiry = 1_000 + 8 * 60 * 60;
    const rotatedAtExpiry = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      expiry
    );

    expect(rotatedAtExpiry?.authorization_id).not.toBe(first?.authorization_id);
    expect(rotatedAtExpiry?.task_id).not.toBe(first?.task_id);
    expect(rotatedAtExpiry?.prepared_at).toBe(expiry);
    expect(control.pendingAuthorizationsForWindow(7, expiry)).toEqual([rotatedAtExpiry]);
    await expect(
      control.decideTaskAuthorization(7, decision(first, 'APPROVE'), runtime(), expiry)
    ).rejects.toThrow('pending authorization');

    const trustedRuntime = runtime();
    await control.decideTaskAuthorization(
      7,
      decision(rotatedAtExpiry, 'REJECT'),
      trustedRuntime,
      expiry + 1
    );
    const saferRequest = { ...request, objective: 'Prepare a read-only release report.' };
    const rotatedAfterRefusal = control.prepareTask(
      7,
      saferRequest,
      '/trusted/workspace',
      trustedRunId(saferRequest.session_id),
      expiry + 2
    );
    expect(rotatedAfterRefusal?.authorization_id).not.toBe(rotatedAtExpiry?.authorization_id);
    expect(rotatedAfterRefusal?.objective).toBe(saferRequest.objective);
    expect(control.pendingAuthorizationsForWindow(7, expiry + 2)).toEqual([rotatedAfterRefusal]);
  });

  it('returns every pending authorization in stable per-window order', async () => {
    const control = new AccordLockTaskControl();
    const first = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const second = control.prepareTask(
      7,
      { ...request, session_id: 'session-2', objective: 'Inspect the changelog.' },
      '/trusted/workspace',
      trustedRunId('session-2'),
      1_001
    );

    expect(control.pendingAuthorizationsForWindow(7, 1_002)).toEqual([first, second]);
    await control.decideTaskAuthorization(7, decision(first, 'REJECT'), runtime(), 1_002);
    expect(control.pendingAuthorizationsForWindow(7, 1_003)).toEqual([second]);
  });

  it('records refusal locally without ever asking the runtime for authority', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = runtime();

    const acknowledgement = await control.decideTaskAuthorization(
      7,
      decision(authorization, 'REJECT'),
      trustedRuntime,
      1_001
    );

    expect(acknowledgement.status).toBe('REJECTED');
    expect(acknowledgement.reason_code).toBe('TASK_AUTHORIZATION_REJECTED');
    expect(trustedRuntime.authorizeTask).not.toHaveBeenCalled();
    await expect(
      control.decideTaskAuthorization(7, decision(authorization, 'APPROVE'), trustedRuntime, 1_002)
    ).rejects.toThrow('different recorded decision');
  });

  it('rejects extra fields, cross-window decisions, and expired approvals', async () => {
    const control = new AccordLockTaskControl();
    expect(() =>
      control.prepareTask(
        7,
        { ...request, extra: true },
        '/trusted/workspace',
        trustedRunId(request.session_id)
      )
    ).toThrow('malformed');
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = runtime();
    await expect(
      control.decideTaskAuthorization(8, decision(authorization, 'APPROVE'), trustedRuntime, 1_001)
    ).rejects.toThrow('pending authorization');
    await expect(
      control.decideTaskAuthorization(
        7,
        decision(authorization, 'APPROVE'),
        trustedRuntime,
        1_000 + 8 * 60 * 60
      )
    ).rejects.toThrow('expired');
    expect(trustedRuntime.authorizeTask).not.toHaveBeenCalled();
  });

  it('revoke pending and rejected tasks without calling the runtime', async () => {
    const control = new AccordLockTaskControl();
    control.prepareTask(7, request, '/trusted/workspace', trustedRunId(request.session_id), 1_000);
    const revoker = revocationRuntime();

    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), revoker)
    ).resolves.toMatchObject({
      session_id: request.session_id,
      status: 'REVOKED',
      reason_code: 'NO_AUTHORIZATION_INSTALLED',
    });
    expect(revoker.revokeSession).not.toHaveBeenCalled();
    expect(control.pendingAuthorizationsForWindow(7, 1_001)).toEqual([]);

    const rejected = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_002
    );
    await control.decideTaskAuthorization(7, decision(rejected, 'REJECT'), runtime(), 1_003);
    await control.revokeSessionAuthorization(7, revocationRequest(), revoker);
    expect(revoker.revokeSession).not.toHaveBeenCalled();
    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), revoker)
    ).resolves.toMatchObject({
      reason_code: 'NO_SESSION_AUTHORIZATION',
      task_id: null,
      run_id: null,
    });
  });

  it('durably revokes the exact approved task before removing it', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = { ...runtime(), ...revocationRuntime() };
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    const acknowledgement = await control.revokeSessionAuthorization(
      7,
      revocationRequest(),
      trustedRuntime
    );

    expect(trustedRuntime.revokeSession).toHaveBeenCalledOnce();
    expect(trustedRuntime.revokeSession).toHaveBeenCalledWith({
      schema_version: 2,
      task_id: authorization?.task_id,
      session_id: request.session_id,
      run_id: trustedRunId(request.session_id),
    });
    expect(acknowledgement).toMatchObject({
      task_id: authorization?.task_id,
      session_id: request.session_id,
      run_id: trustedRunId(request.session_id),
      reason_code: 'TASK_AUTHORIZATION_REVOKED',
    });
  });

  it('waits for an in-flight authorization and then revokes its resulting authority', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const deferred = deferredRuntime();
    const revoker = revocationRuntime();
    const trustedRuntime = { ...deferred.trustedRuntime, ...revoker };
    const authorizationDecision = control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );
    await vi.waitFor(() => expect(deferred.trustedRuntime.authorizeTask).toHaveBeenCalledOnce());

    const revocation = control.revokeSessionAuthorization(7, revocationRequest(), trustedRuntime);
    expect(revoker.revokeSession).not.toHaveBeenCalled();
    deferred.complete();

    await expect(authorizationDecision).resolves.toMatchObject({ status: 'APPROVED' });
    await expect(revocation).resolves.toMatchObject({ reason_code: 'TASK_AUTHORIZATION_REVOKED' });
    expect(revoker.revokeSession).toHaveBeenCalledOnce();
  });

  it('keeps approved state on revocation failure so an exact retry can finish revocation', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const approved = runtime();
    const successful = revocationRuntime();
    const revokeSession = vi
      .fn()
      .mockRejectedValueOnce(new Error('control channel lost'))
      .mockImplementation(successful.revokeSession);
    const trustedRuntime = { ...approved, revokeSession };
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), trustedRuntime)
    ).rejects.toThrow('control channel lost');
    expect(
      control.prepareTask(7, request, '/trusted/workspace', trustedRunId(request.session_id), 1_002)
    ).toBeNull();
    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), trustedRuntime)
    ).resolves.toMatchObject({ reason_code: 'TASK_AUTHORIZATION_REVOKED' });
    expect(revokeSession).toHaveBeenCalledTimes(2);
  });

  it('revoke every window session through one serialized control-channel queue', async () => {
    const control = new AccordLockTaskControl();
    const first = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const secondRequest = { ...request, session_id: 'session-2' };
    const second = control.prepareTask(
      7,
      secondRequest,
      '/trusted/workspace',
      trustedRunId(secondRequest.session_id),
      1_000
    );
    const approver = runtime();
    const revoker = revocationRuntime();
    const trustedRuntime = { ...approver, ...revoker };
    await Promise.all([
      control.decideTaskAuthorization(7, decision(first, 'APPROVE'), trustedRuntime, 1_001),
      control.decideTaskAuthorization(7, decision(second, 'APPROVE'), trustedRuntime, 1_001),
    ]);

    const acknowledgements = await control.revokeWindowAuthorizations(7, trustedRuntime);

    expect(acknowledgements).toHaveLength(2);
    expect(revoker.revokeSession).toHaveBeenCalledTimes(2);
    expect(control.pendingAuthorizationsForWindow(7, 1_002)).toEqual([]);
    await expect(
      control.revokeSessionAuthorization(8, { ...revocationRequest(), extra: true }, trustedRuntime)
    ).rejects.toThrow('malformed');
  });

  it('revoke runtime authority before invoking an explicit renderer reload', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const order: string[] = [];
    const trustedRuntime = {
      ...runtime(),
      revokeSession: vi.fn(async (revocation: SessionRevocation) => {
        order.push('revoke');
        return {
          requestId: '22222222-2222-4222-8222-222222222222',
          code: 'SESSION_REVOKED' as const,
          revocationDigest: accordLockDigest(revocation),
          taskId: revocation.task_id,
          sessionId: revocation.session_id,
          runId: revocation.run_id,
        };
      }),
    };
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    await revokeBeforeAccordLockWindowReload(
      7,
      () => {
        order.push('reloaded');
      },
      control,
      trustedRuntime
    );

    expect(order).toEqual(['revoke', 'reloaded']);
    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), trustedRuntime)
    ).resolves.toMatchObject({ reason_code: 'NO_SESSION_AUTHORIZATION' });
  });

  it('never reloads when runtime revocation fails', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = {
      ...runtime(),
      revokeSession: vi.fn().mockRejectedValue(new Error('control channel lost')),
    };
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );
    const reload = vi.fn();

    await expect(
      revokeBeforeAccordLockWindowReload(7, reload, control, trustedRuntime)
    ).rejects.toThrow('control channel lost');

    expect(reload).not.toHaveBeenCalled();
  });

  it('blocks an unexpected top-level navigation before starting revocation', () => {
    const order: string[] = [];
    const event = {
      preventDefault: vi.fn(() => order.push('blocked')),
    };

    interceptUnexpectedAccordLockTopLevelNavigation(event, () => order.push('revocation'));

    expect(event.preventDefault).toHaveBeenCalledOnce();
    expect(order).toEqual(['blocked', 'revocation']);
  });

  it('removes runtime authority when a renderer process disappears', async () => {
    const control = new AccordLockTaskControl();
    const authorization = control.prepareTask(
      7,
      request,
      '/trusted/workspace',
      trustedRunId(request.session_id),
      1_000
    );
    const trustedRuntime = { ...runtime(), ...revocationRuntime() };
    await control.decideTaskAuthorization(
      7,
      decision(authorization, 'APPROVE'),
      trustedRuntime,
      1_001
    );

    await revokeAccordLockWindowAuthorizations(7, control, trustedRuntime);

    await expect(
      control.revokeSessionAuthorization(7, revocationRequest(), trustedRuntime)
    ).resolves.toMatchObject({ reason_code: 'NO_SESSION_AUTHORIZATION' });
    expect(trustedRuntime.revokeSession).toHaveBeenCalledOnce();
  });
});
