import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { AccordLockApprovalRequest } from './accordlockApprovalProxy';
import type { ApprovedSession } from './accordlockRuntime';
import {
  accordLockActionApprovalRequestDigest,
  bindAccordLockActionApproval,
  canApproveAccordLockAction,
  formatAccordLockActionApprovalDetail,
  parseAccordLockActionApprovalChallenge,
  type AccordLockActionApprovalRequest,
} from './accordlockActionApproval';

const taskId = '12345678-1234-4abc-8def-123456789abc';
const approvalId = '87654321-4321-4abc-8def-cba987654321';
const taskPolicyHash = `sha256:${'a'.repeat(64)}`;
const prestateHash = `sha256:${'b'.repeat(64)}`;
const objectiveHash = `sha256:${'c'.repeat(64)}`;
const actionHash = `sha256:${'d'.repeat(64)}`;
const requirementHash = `sha256:${'e'.repeat(64)}`;
const transformationStepHash = `sha256:${'f'.repeat(64)}`;
const policyDecisionHash = `sha256:${'1'.repeat(64)}`;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function fixture(
  tool: 'write' | 'edit' = 'write',
  overrides: { request?: Record<string, unknown>; response?: Record<string, unknown> } = {}
): AccordLockApprovalRequest {
  const defaultArgs =
    tool === 'write'
      ? { path: 'src/message.txt', content: 'hello\nworld' }
      : { path: 'src/message.txt', before: 'hello', after: 'goodbye' };
  const args = (overrides.request?.arguments ?? defaultArgs) as typeof defaultArgs;
  const planMaterial = {
    text: [],
    tool_requests: [{ id: 'call-1', name: `developer__${tool}`, arguments_sha256: digest(args) }],
  };
  const proposal = {
    schema_version: 3,
    session_id: 'session-1',
    run_id: 'sha256:run-binding',
    tool_call_id: 'call-1',
    workspace_root: 'C:\\workspace',
    extension_id: 'developer',
    tool_name: tool,
    arguments: args,
    arguments_sha256: digest(args),
    agent_plan_checkpoint: {
      schema_version: 1,
      session_id: 'session-1',
      run_id: 'sha256:run-binding',
      tool_call_id: 'call-1',
      material: planMaterial,
      material_sha256: digest(planMaterial),
      recorded_at: 1_800_000_000,
    },
    ...overrides.request,
  };
  const proposalDigest = digest(proposal);
  const requestedText =
    tool === 'write' ? (args as { content: string }).content : (args as { after: string }).after;
  const approvalRequest: AccordLockActionApprovalRequest = {
    schema_version: 2,
    task_id: taskId,
    session_id: String(proposal.session_id),
    run_id: String(proposal.run_id),
    tool_call_id: String(proposal.tool_call_id),
    proposal_digest: proposalDigest,
    task_policy_hash: taskPolicyHash,
    prestate_hash: prestateHash,
    action: {
      extension_id: 'developer',
      tool_name: tool,
      relative_path: args.path,
      action_type: tool === 'write' ? 'CREATE_FILE' : 'EDIT_FILE',
      requested_bytes: Buffer.byteLength(requestedText, 'utf8'),
    },
    task_requirement: {
      schema_version: 2,
      requirement_id: '11111111-1111-4111-8111-111111111111',
      task_hash: taskPolicyHash,
      statement_hash: objectiveHash,
      minimum_score: 1_000_000,
    },
    transformation_step: {
      schema_version: 2,
      step_id: '22222222-2222-4222-8222-222222222222',
      task_hash: taskPolicyHash,
      sequence: 0,
      parent_step_hash: null,
      source_stage: 'REQUEST',
      source_hash: objectiveHash,
      target_stage: 'ACTION',
      target_hash: actionHash,
      recorded_at: 100,
    },
    policy_decision: {
      schema_version: 2,
      decision_id: '33333333-3333-4333-8333-333333333333',
      task_hash: taskPolicyHash,
      action_hash: actionHash,
      sequence: 0,
      parent_decision_hash: null,
      requirement_hashes: [requirementHash],
      transformation_step_hashes: [transformationStepHash],
      conformance_evaluation_hashes: [],
      resource_request_hashes: [],
      resource_quota_hashes: [],
      resource_reservation_hashes: [],
      baseline_decision: 'ALLOW',
      decision: 'REQUIRE_APPROVAL',
      reasons: ['CONFORMANCE_EVALUATION_MISSING'],
      policy_epoch: 1,
      evaluated_at: 100,
    },
    policy_decision_hash: policyDecisionHash,
  };
  const response = {
    schema_version: 3,
    proposal_digest: proposalDigest,
    status: 'APPROVAL_REQUIRED',
    reason_code: 'ACTION_APPROVAL_REQUIRED',
    approval_request: approvalRequest,
    approval_request_hash: accordLockActionApprovalRequestDigest(approvalRequest),
    ...overrides.response,
  };
  return {
    path: '/api/v2/execution/filesystem/authorize-and-execute',
    requestBody: Buffer.from(JSON.stringify({ schema_version: 3, proposal }), 'utf8'),
    responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
  };
}

function terminalApprovalFixture(): AccordLockApprovalRequest {
  const base = fixture();
  const request = JSON.parse(Buffer.from(base.requestBody).toString('utf8')) as {
    proposal: Record<string, unknown>;
  };
  const response = JSON.parse(Buffer.from(base.responseBody).toString('utf8')) as {
    proposal_digest: string;
    approval_request: AccordLockActionApprovalRequest;
    approval_request_hash: string;
  };
  const proposal = request.proposal;
  proposal.extension_id = 'developer';
  proposal.tool_name = 'shell';
  proposal.arguments = {
    argv: ['cargo', 'test', '--lib'],
    cwd: '.',
    env: { CI: '1', NO_COLOR: '1' },
    timeout_seconds: 60,
    max_output_bytes: 65_536,
  };
  proposal.arguments_sha256 = digest(proposal.arguments);
  const proposalDigest = digest(proposal);
  const approvalRequest = response.approval_request;
  approvalRequest.proposal_digest = proposalDigest;
  approvalRequest.action = {
    extension_id: 'developer',
    tool_name: 'shell',
    relative_path: '.',
    action_type: 'EXECUTE_PROCESS',
    requested_bytes: 11,
    executable_path: 'C:\\Program Files\\AccordLock\\probe.exe',
    executable_sha256: `sha256:${'7'.repeat(64)}`,
  };
  response.proposal_digest = proposalDigest;
  response.approval_request_hash = accordLockActionApprovalRequestDigest(approvalRequest);
  return {
    path: '/api/v2/execution/terminal/authorize-and-execute',
    requestBody: Buffer.from(JSON.stringify(request), 'utf8'),
    responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
  };
}

function networkApprovalFixture(): AccordLockApprovalRequest {
  const base = fixture();
  const request = JSON.parse(Buffer.from(base.requestBody).toString('utf8')) as {
    proposal: Record<string, unknown>;
  };
  const response = JSON.parse(Buffer.from(base.responseBody).toString('utf8')) as {
    proposal_digest: string;
    approval_request: AccordLockActionApprovalRequest;
    approval_request_hash: string;
  };
  const proposal = request.proposal;
  proposal.extension_id = 'accordlock_network';
  proposal.tool_name = 'https_request';
  proposal.arguments = {
    method: 'GET',
    url: 'https://api.example.com/v1/releases?channel=stable',
    headers: [],
    body: null,
    timeout_seconds: 30,
    max_response_bytes: 65_536,
    redirect_policy: 'DENY',
  };
  proposal.arguments_sha256 = digest(proposal.arguments);
  const proposalDigest = digest(proposal);
  const approvalRequest = response.approval_request;
  approvalRequest.proposal_digest = proposalDigest;
  approvalRequest.action = {
    extension_id: 'accordlock_network',
    tool_name: 'https_request',
    relative_path: 'api.example.com/v1/releases?channel=stable',
    action_type: 'HTTPS_REQUEST',
    requested_bytes: 0,
  };
  response.proposal_digest = proposalDigest;
  response.approval_request_hash = accordLockActionApprovalRequestDigest(approvalRequest);
  return {
    path: '/api/v2/execution/network/authorize-and-execute',
    requestBody: Buffer.from(JSON.stringify(request), 'utf8'),
    responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
  };
}

function deleteApprovalFixture(): AccordLockApprovalRequest {
  const base = fixture();
  const request = JSON.parse(Buffer.from(base.requestBody).toString('utf8')) as {
    proposal: Record<string, unknown>;
  };
  const response = JSON.parse(Buffer.from(base.responseBody).toString('utf8')) as {
    proposal_digest: string;
    approval_request: AccordLockActionApprovalRequest;
    approval_request_hash: string;
  };
  const proposal = request.proposal;
  proposal.tool_name = 'delete_file';
  proposal.arguments = { path: 'src/message.txt' };
  proposal.arguments_sha256 = digest(proposal.arguments);
  const proposalDigest = digest(proposal);
  const approvalRequest = response.approval_request;
  approvalRequest.proposal_digest = proposalDigest;
  approvalRequest.action = {
    extension_id: 'developer',
    tool_name: 'delete_file',
    relative_path: 'src/message.txt',
    action_type: 'DELETE_FILE',
    requested_bytes: 11,
  };
  response.proposal_digest = proposalDigest;
  response.approval_request_hash = accordLockActionApprovalRequestDigest(approvalRequest);
  return {
    path: '/api/v2/execution/filesystem/authorize-and-execute',
    requestBody: Buffer.from(JSON.stringify(request), 'utf8'),
    responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
  };
}

function authorizedSession(): ApprovedSession {
  const taskObjective = 'Authorize the requested file operation.';
  return {
    schema_version: 3,
    task_id: taskId,
    session_id: 'session-1',
    run_id: 'sha256:run-binding',
    workspace_root: 'C:\\workspace',
    task_objective: taskObjective,
    policy_epoch: 1,
    task_policy: {
      schema_version: 2,
      task_objective_hash: `sha256:${createHash('sha256').update(taskObjective, 'utf8').digest('hex')}`,
      preauthorized_capabilities: [
        { extension_id: 'developer', tool_name: 'read' },
        { extension_id: 'developer', tool_name: 'tree' },
      ],
      protected_paths: ['.env', '.git'],
    },
    task_policy_hash: taskPolicyHash,
    capabilities: [
      { extension_id: 'developer', tool_name: 'delete_file' },
      { extension_id: 'developer', tool_name: 'edit' },
      { extension_id: 'developer', tool_name: 'read' },
      { extension_id: 'developer', tool_name: 'shell' },
      { extension_id: 'developer', tool_name: 'tree' },
      { extension_id: 'developer', tool_name: 'write' },
    ],
    approved_at: 1_000,
    expires_at: 2_000,
  };
}

function authorizedNetworkSession(): ApprovedSession {
  const session = authorizedSession();
  return {
    ...session,
    capabilities: [
      { extension_id: 'accordlock_network', tool_name: 'https_request' },
      ...session.capabilities,
    ],
  };
}

describe('AccordLock native action approval binding', () => {
  it('accepts the current v3 execution exchange and rejects stale v2 envelopes', () => {
    const current = fixture();
    expect(() => parseAccordLockActionApprovalChallenge(current)).not.toThrow();

    const staleRequest = JSON.parse(Buffer.from(current.requestBody).toString('utf8')) as {
      schema_version: number;
    };
    staleRequest.schema_version = 2;
    expect(() =>
      parseAccordLockActionApprovalChallenge({
        ...current,
        requestBody: Buffer.from(JSON.stringify(staleRequest), 'utf8'),
      })
    ).toThrow('AccordLock protected-action request is malformed');

    const staleResponse = JSON.parse(Buffer.from(current.responseBody).toString('utf8')) as {
      schema_version: number;
    };
    staleResponse.schema_version = 2;
    expect(() =>
      parseAccordLockActionApprovalChallenge({
        ...current,
        responseBody: Buffer.from(JSON.stringify(staleResponse), 'utf8'),
      })
    ).toThrow('AccordLock runtime did not return an exact approval request');
  });

  it.each([
    ['write', 'Create file', 'hello\nworld'],
    ['edit', 'Edit file', 'Before\nhello\n\nAfter\ngoodbye'],
  ] as const)('parses an exact %s challenge', (tool, label, preview) => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture(tool));

    expect(challenge.operationLabel).toBe(label);
    expect(challenge.approvalRequest.action.relative_path).toBe('src/message.txt');
    expect(challenge.preview).toBe(preview);
    expect(challenge.approvalRequestHash).toBe(
      accordLockActionApprovalRequestDigest(challenge.approvalRequest)
    );
  });

  it('builds a short-lived approval bound to the exact action', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());
    const approval = bindAccordLockActionApproval(
      challenge,
      authorizedSession(),
      'APPROVED',
      approvalId,
      1_100
    );

    expect(approval.decision).toBe('APPROVED');
    expect(approval.approval_request_hash).toBe(challenge.approvalRequestHash);
    expect(approval.proposal_digest).toBe(challenge.proposalDigest);
    expect(approval.prestate_hash).toBe(prestateHash);
    expect(approval.task_requirement).toEqual(challenge.approvalRequest.task_requirement);
    expect(approval.transformation_step).toEqual(challenge.approvalRequest.transformation_step);
    expect(approval.policy_decision).toEqual(challenge.approvalRequest.policy_decision);
    expect(approval.policy_decision_hash).toBe(policyDecisionHash);
    expect(approval.expires_at).toBe(1_220);
    expect(approval.approval_evidence_hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it('parses and binds an exact direct-argv terminal action approval', () => {
    const challenge = parseAccordLockActionApprovalChallenge(terminalApprovalFixture());

    expect(challenge.operationLabel).toBe('Run program');
    expect(challenge.targetLabel).toBe('Working directory');
    expect(challenge.target).toBe('.');
    expect(challenge.preview).toContain('0: "cargo"');
    const approval = bindAccordLockActionApproval(
      challenge,
      authorizedSession(),
      'APPROVED',
      approvalId,
      1_100
    );
    expect(approval.policy_decision).toEqual(challenge.approvalRequest.policy_decision);
    expect(approval.policy_decision_hash).toBe(challenge.approvalRequest.policy_decision_hash);
  });

  it('parses and binds one exact read-only HTTPS request', () => {
    const challenge = parseAccordLockActionApprovalChallenge(networkApprovalFixture());

    expect(challenge.operationLabel).toBe('Read website');
    expect(challenge.targetLabel).toBe('Destination');
    expect(challenge.target).toBe('api.example.com/v1/releases?channel=stable');
    expect(challenge.quantityLabel).toBe('Response limit');
    expect(challenge.preview).toContain('GET https://api.example.com/v1/releases?channel=stable');
    expect(challenge.preview).toContain('headers: none');
    expect(challenge.preview).toContain('redirects: blocked');

    const approval = bindAccordLockActionApproval(
      challenge,
      authorizedNetworkSession(),
      'APPROVED',
      approvalId,
      1_100
    );
    expect(approval.decision).toBe('APPROVED');
    expect(approval.approval_request_hash).toBe(challenge.approvalRequestHash);
  });

  it.each([
    ['POST', { method: 'POST' }],
    ['request header', { headers: [{ name: 'authorization', value: 'secret' }] }],
    ['body', { body: 'payload' }],
    ['redirect following', { redirect_policy: 'FOLLOW' }],
    ['embedded credentials', { url: 'https://user:secret@api.example.com/v1' }],
    ['local destination', { url: 'https://127.0.0.1/v1' }],
  ])('keeps a network approval locked when it contains %s', (_label, mutation) => {
    const original = networkApprovalFixture();
    const request = JSON.parse(Buffer.from(original.requestBody).toString('utf8')) as {
      proposal: { arguments: Record<string, unknown> };
    };
    Object.assign(request.proposal.arguments, mutation);

    expect(() =>
      parseAccordLockActionApprovalChallenge({
        ...original,
        requestBody: Buffer.from(JSON.stringify(request), 'utf8'),
      })
    ).toThrow();
  });

  it('parses and binds an exact recoverable delete-file approval', () => {
    const challenge = parseAccordLockActionApprovalChallenge(deleteApprovalFixture());

    expect(challenge.operationLabel).toBe('Move file to recovery storage');
    expect(challenge.target).toBe('src/message.txt');
    expect(challenge.quantityLabel).toBe('Current file');
    expect(challenge.contentEvidence).toContain('11 bytes');
    expect(challenge.preview).toContain('recovery storage');
    expect(challenge.approvalRequest.action.action_type).toBe('DELETE_FILE');
    const approval = bindAccordLockActionApproval(
      challenge,
      authorizedSession(),
      'APPROVED',
      approvalId,
      1_100
    );
    expect(approval.decision).toBe('APPROVED');
    expect(approval.prestate_hash).toBe(prestateHash);
  });

  it('rejects recursive delete-file argument substitution', () => {
    const original = deleteApprovalFixture();
    const request = JSON.parse(Buffer.from(original.requestBody).toString('utf8')) as {
      proposal: Record<string, unknown>;
    };
    request.proposal.arguments = { path: 'src', recursive: true };
    request.proposal.arguments_sha256 = digest(request.proposal.arguments);
    expect(() =>
      parseAccordLockActionApprovalChallenge({
        ...original,
        requestBody: Buffer.from(JSON.stringify(request), 'utf8'),
      })
    ).toThrow();
  });

  it('records an explicit DENIED resolution with a different evidence commitment', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());
    const allowed = bindAccordLockActionApproval(
      challenge,
      authorizedSession(),
      'APPROVED',
      approvalId,
      1_100
    );
    const denied = bindAccordLockActionApproval(
      challenge,
      authorizedSession(),
      'DENIED',
      approvalId,
      1_100
    );

    expect(denied.decision).toBe('DENIED');
    expect(denied.approval_evidence_hash).not.toBe(allowed.approval_evidence_hash);
  });

  it.each([
    ['wrong status', { status: 'DENIED' }],
    ['wrong reason', { reason_code: 'ALLOWED' }],
    ['wrong proposal', { proposal_digest: `sha256:${'d'.repeat(64)}` }],
    ['wrong approval request hash', { approval_request_hash: `sha256:${'e'.repeat(64)}` }],
    ['extra field', { injected_safe: true }],
  ])('rejects a runtime response with %s', (_, response) => {
    expect(() => parseAccordLockActionApprovalChallenge(fixture('write', { response }))).toThrow();
  });

  it('rejects proposal mutation after the runtime approval request', () => {
    const original = fixture();
    const request = JSON.parse(Buffer.from(original.requestBody).toString('utf8')) as {
      proposal: Record<string, unknown>;
    };
    request.proposal.arguments = { path: 'src/message.txt', content: 'changed' };
    const mutated = { ...original, requestBody: Buffer.from(JSON.stringify(request), 'utf8') };

    expect(() => parseAccordLockActionApprovalChallenge(mutated)).toThrow();
  });

  it.each(['policy_decision', 'policy_decision_hash'] as const)(
    'rejects hostile %s substitution in the runtime approval request',
    (field) => {
      const original = fixture();
      const response = JSON.parse(Buffer.from(original.responseBody).toString('utf8')) as {
        approval_request: Record<string, unknown>;
      };
      if (field === 'policy_decision') {
        response.approval_request.policy_decision = {
          ...(response.approval_request.policy_decision as Record<string, unknown>),
          action_hash: `sha256:${'9'.repeat(64)}`,
        };
      } else {
        response.approval_request.policy_decision_hash = `sha256:${'9'.repeat(64)}`;
      }
      const substituted = {
        ...original,
        responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
      };

      expect(() => parseAccordLockActionApprovalChallenge(substituted)).toThrow();
    }
  );

  it('prevents policy decision mutation between challenge display and private approval', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());

    expect(
      () =>
        ((challenge.approvalRequest.policy_decision as Record<string, unknown>).decision = 'ALLOW')
    ).toThrow();
    expect(challenge.approvalRequest.policy_decision.decision).toBe('REQUIRE_APPROVAL');
    expect(() =>
      bindAccordLockActionApproval(challenge, authorizedSession(), 'APPROVED', approvalId, 1_100)
    ).not.toThrow();

    const tampered = {
      ...challenge,
      approvalRequest: {
        ...challenge.approvalRequest,
        policy_decision: {
          ...challenge.approvalRequest.policy_decision,
          decision: 'ALLOW',
        },
      },
    } as typeof challenge;
    expect(() =>
      bindAccordLockActionApproval(tampered, authorizedSession(), 'APPROVED', approvalId, 1_100)
    ).toThrow();
  });

  it('rejects a cross-task, cross-workspace, or expired binding', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());

    expect(() =>
      bindAccordLockActionApproval(
        challenge,
        { ...authorizedSession(), workspace_root: 'C:\\other' },
        'APPROVED',
        approvalId,
        1_100
      )
    ).toThrow();
    expect(() =>
      bindAccordLockActionApproval(
        challenge,
        { ...authorizedSession(), task_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
        'APPROVED',
        approvalId,
        1_100
      )
    ).toThrow();
    expect(() =>
      bindAccordLockActionApproval(challenge, authorizedSession(), 'APPROVED', approvalId, 2_000)
    ).toThrow();
  });

  it('sanitizes control and bidi characters in the native detail', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());
    const detail = formatAccordLockActionApprovalDetail(
      { ...challenge, preview: `safe\u202esecret`, previewTruncated: false },
      `objective\u0000${'y'.repeat(2_000)}`
    );

    expect(detail).not.toContain('\u0000');
    expect(detail).not.toContain('\u202e');
    expect(detail).toContain('… task text shortened here');
    expect(detail).toContain('PROPOSED CHANGE — UNTRUSTED');
  });

  it('describes the exact filesystem prestate guarantee for file operations', () => {
    const detail = formatAccordLockActionApprovalDetail(
      parseAccordLockActionApprovalChallenge(fixture()),
      'Update the message'
    );

    expect(detail).toContain('File prestate: exact state will be revalidated');
    expect(detail).not.toContain('indirect process changes');
  });

  it('describes terminal commitments without claiming a sandbox', () => {
    const detail = formatAccordLockActionApprovalDetail(
      parseAccordLockActionApprovalChallenge(terminalApprovalFixture()),
      'Run the tests'
    );

    expect(detail).toContain('executable, working directory, arguments, and environment');
    expect(detail).toContain('Executable: C:\\Program Files\\AccordLock\\probe.exe');
    expect(detail).toContain(`Executable SHA-256: sha256:${'7'.repeat(64)}`);
    expect(detail).toContain('not sandboxed and may affect the system beyond this workspace');
    expect(detail).toContain('path and hash are checked immediately before launch');
    expect(detail).not.toContain('exact execution only');
    expect(detail).not.toContain('File prestate');
  });

  it('rejects executable identity substitution inside an existing terminal challenge', () => {
    const original = terminalApprovalFixture();
    const response = JSON.parse(Buffer.from(original.responseBody).toString('utf8')) as {
      approval_request: { action: { executable_sha256: string } };
    };
    response.approval_request.action.executable_sha256 = `sha256:${'8'.repeat(64)}`;

    expect(() =>
      parseAccordLockActionApprovalChallenge({
        ...original,
        responseBody: Buffer.from(JSON.stringify(response), 'utf8'),
      })
    ).toThrow();
  });

  it('describes the committed request and destination for future network requests', () => {
    const challenge = parseAccordLockActionApprovalChallenge(terminalApprovalFixture());
    const networkChallenge = {
      ...challenge,
      approvalRequest: {
        ...challenge.approvalRequest,
        action: { ...challenge.approvalRequest.action, action_type: 'HTTPS_REQUEST' },
      },
    } as unknown as typeof challenge;
    const detail = formatAccordLockActionApprovalDetail(
      networkChallenge,
      'Fetch the release manifest'
    );

    expect(detail).toContain('exact request and destination are committed and revalidated');
    expect(detail).not.toContain('File prestate');
  });

  it('allows a normal file through the compact preview because native review shows it in full', () => {
    const challenge = parseAccordLockActionApprovalChallenge(
      fixture('write', {
        request: {
          arguments: { path: 'src/message.txt', content: 'x'.repeat(1_601) },
          arguments_sha256: digest({ path: 'src/message.txt', content: 'x'.repeat(1_601) }),
        },
      })
    );

    expect(challenge.previewTruncated).toBe(true);
    expect(canApproveAccordLockAction(challenge)).toBe(true);
  });

  it('keeps oversized file content locked before native review', () => {
    const content = 'x'.repeat(256 * 1024 + 1);
    const challenge = parseAccordLockActionApprovalChallenge(
      fixture('write', {
        request: {
          arguments: { path: 'src/generated.txt', content },
          arguments_sha256: digest({ path: 'src/generated.txt', content }),
        },
      })
    );

    expect(canApproveAccordLockAction(challenge)).toBe(false);
  });

  it('freezes the exact parsed action while a decision is pending', () => {
    const challenge = parseAccordLockActionApprovalChallenge(fixture());

    expect(Object.isFrozen(challenge)).toBe(true);
    expect(Object.isFrozen(challenge.arguments)).toBe(true);
    expect(Object.isFrozen(challenge.approvalRequest)).toBe(true);
    expect(Object.isFrozen(challenge.approvalRequest.action)).toBe(true);
    expect(() => {
      if (challenge.arguments.kind === 'write') challenge.arguments.content = 'different';
    }).toThrow();
  });

  it('rejects invisible path characters before they can spoof a native prompt', () => {
    expect(() =>
      parseAccordLockActionApprovalChallenge(
        fixture('write', {
          request: {
            arguments: { path: 'src/\u202esecret.txt', content: 'hello\nworld' },
            arguments_sha256: digest({
              path: 'src/\u202esecret.txt',
              content: 'hello\nworld',
            }),
          },
        })
      )
    ).toThrow();
  });
});
