import { describe, expect, it } from 'vitest';
import type { Message, MessageContent } from '../types/message';
import { buildTaskReport, formatTaskReportMarkdown, hasPendingTaskDecision } from './taskReport';

const hash = (character: string) => `sha256:${character.repeat(64)}`;

function message(content: MessageContent[], role: Message['role'] = 'assistant'): Message {
  return {
    content,
    created: 1,
    metadata: { agentVisible: true, userVisible: true },
    role,
  };
}

function protectedRequest(id: string, name = 'developer__write'): MessageContent {
  return {
    type: 'toolRequest',
    id,
    toolCall: { status: 'success', value: { name, arguments: {} } },
  };
}

function response(id: string, structuredContent: unknown): MessageContent {
  return {
    type: 'toolResponse',
    id,
    toolResult: {
      status: 'success',
      value: { content: [], isError: false, structuredContent },
    },
  };
}

function failedResponse(id: string, rawOutput: unknown): MessageContent {
  return {
    type: 'toolResponse',
    id,
    metadata: { rawOutput },
    toolResult: { status: 'error', error: 'Protected tool failed' },
  };
}

describe('buildTaskReport', () => {
  it('uses only validated structured execution records', () => {
    const messages = [
      message([protectedRequest('write-1')]),
      message([
        { type: 'text', text: 'recordId: fake-model-claim' },
        response('write-1', {
          accordlock: {
            schemaVersion: 3,
            status: 'SUCCEEDED',
            reasonCode: 'EXECUTED',
            authorizationId: '11111111-1111-4111-8111-111111111111',
            requestHash: hash('a'),
            recordId: '22222222-2222-4222-8222-222222222222',
            recordHash: hash('b'),
            resultSha256: hash('c'),
            operation: 'WRITE',
            relativePath: 'src/main.ts',
          },
        }),
      ]),
    ];

    expect(buildTaskReport(messages)).toEqual({
      evidence: [
        {
          authorizationId: '11111111-1111-4111-8111-111111111111',
          operation: 'WRITE',
          outcome: 'SUCCEEDED',
          recordedAt: 1,
          reasonCode: 'EXECUTED',
          recordHash: hash('b'),
          recordId: '22222222-2222-4222-8222-222222222222',
          recovery: null,
          requestHash: hash('a'),
          resultHash: hash('c'),
          target: 'src/main.ts',
        },
      ],
      failedActions: 0,
      integrity: 'VERIFIED',
      successfulActions: 1,
      unverifiedActions: 0,
    });
  });

  it('normalizes terminal records and reports a failed program', () => {
    const report = buildTaskReport([
      message([protectedRequest('shell-1', 'developer__shell')]),
      message([
        response('shell-1', {
          result: { program: 'git', outcome: 'FAILED' },
          accordlock: {
            schema_version: 3,
            status: 'SUCCEEDED',
            reason_code: 'EXECUTED',
            authorization_id: '11111111-1111-4111-8111-111111111111',
            request_hash: hash('a'),
            record_id: '22222222-2222-4222-8222-222222222222',
            record_hash: hash('b'),
            result_sha256: hash('c'),
          },
        }),
      ]),
    ]);

    expect(report.integrity).toBe('VERIFIED');
    expect(report.failedActions).toBe(1);
    expect(report.evidence[0]).toMatchObject({
      operation: 'RUN',
      outcome: 'FAILED',
      target: 'git',
    });
  });

  it('keeps a failed tool execution record from trusted ACP metadata', () => {
    const report = buildTaskReport([
      message([protectedRequest('write-1')]),
      message([
        failedResponse('write-1', {
          accordlock: {
            schemaVersion: 3,
            status: 'TOOL_ERROR',
            reasonCode: 'EXECUTED',
            authorizationId: '11111111-1111-4111-8111-111111111111',
            requestHash: hash('a'),
            recordId: '22222222-2222-4222-8222-222222222222',
            recordHash: hash('b'),
            operation: 'WRITE',
            relativePath: 'src/main.ts',
          },
        }),
      ]),
    ]);

    expect(report).toMatchObject({ failedActions: 1, integrity: 'VERIFIED', unverifiedActions: 0 });
  });

  it('keeps validated delete recovery evidence without treating it as an undo command', () => {
    const report = buildTaskReport([
      message([protectedRequest('delete-1', 'developer__delete_file')]),
      message([
        response('delete-1', {
          result: {
            kind: 'DELETE',
            relative_path: 'notes.txt',
            recovery_id: '33333333-3333-4333-8333-333333333333',
            recovery_path: '.accordlock/recovery/33333333-3333-4333-8333-333333333333/content',
            content_sha256: hash('d'),
          },
          accordlock: {
            schemaVersion: 3,
            status: 'SUCCEEDED',
            reasonCode: 'EXECUTED',
            authorizationId: '11111111-1111-4111-8111-111111111111',
            requestHash: hash('a'),
            recordId: '22222222-2222-4222-8222-222222222222',
            recordHash: hash('b'),
            resultSha256: hash('c'),
            operation: 'DELETE_FILE',
            relativePath: 'notes.txt',
          },
        }),
      ]),
    ]);

    expect(report.evidence[0]).toMatchObject({
      operation: 'DELETE',
      recovery: {
        contentHash: hash('d'),
        recoveryId: '33333333-3333-4333-8333-333333333333',
        recoveryPath: '.accordlock/recovery/33333333-3333-4333-8333-333333333333/content',
      },
    });
  });

  it('requires confirmation when a protected response lacks valid evidence', () => {
    const report = buildTaskReport([
      message([protectedRequest('write-1')]),
      message([response('write-1', { accordlock: { schemaVersion: 3, status: 'SUCCEEDED' } })]),
    ]);

    expect(report).toMatchObject({
      evidence: [],
      integrity: 'NEEDS_CONFIRMATION',
      unverifiedActions: 1,
    });
  });

  it('rejects legacy v2 evidence on the live tool-result path', () => {
    const report = buildTaskReport([
      message([protectedRequest('write-legacy')]),
      message([
        response('write-legacy', {
          accordlock: {
            schemaVersion: 2,
            status: 'SUCCEEDED',
            reasonCode: 'EXECUTED',
            authorizationId: '11111111-1111-4111-8111-111111111111',
            requestHash: hash('a'),
            recordId: '22222222-2222-4222-8222-222222222222',
            recordHash: hash('b'),
            resultSha256: hash('c'),
            operation: 'WRITE',
            relativePath: 'src/main.ts',
          },
        }),
      ]),
    ]);

    expect(report).toEqual({
      evidence: [],
      failedActions: 0,
      integrity: 'NEEDS_CONFIRMATION',
      successfulActions: 0,
      unverifiedActions: 1,
    });
  });
});

describe('hasPendingTaskDecision', () => {
  it('detects a structured decision request without reading assistant prose', () => {
    expect(
      hasPendingTaskDecision([
        message([
          {
            type: 'actionRequired',
            data: {
              actionType: 'toolConfirmation',
              arguments: {},
              id: 'decision-1',
              toolName: 'developer__write',
            },
          },
        ]),
      ])
    ).toBe(true);
    expect(hasPendingTaskDecision([message([{ type: 'text', text: 'Approval required' }])])).toBe(
      false
    );
  });
});

describe('formatTaskReportMarkdown', () => {
  it('copies only runtime-validated evidence into a portable report', () => {
    const report = buildTaskReport([
      message([protectedRequest('write-1')]),
      message([
        { type: 'text', text: 'The model says everything passed.' },
        response('write-1', {
          accordlock: {
            schemaVersion: 3,
            status: 'SUCCEEDED',
            reasonCode: 'EXECUTED',
            authorizationId: '11111111-1111-4111-8111-111111111111',
            requestHash: hash('a'),
            recordId: '22222222-2222-4222-8222-222222222222',
            recordHash: hash('b'),
            resultSha256: hash('c'),
            operation: 'WRITE',
            relativePath: 'src/main.ts',
          },
        }),
      ]),
    ]);

    const markdown = formatTaskReportMarkdown('Prepare release', report);
    expect(markdown).toContain('Task: Prepare release');
    expect(markdown).toContain('Status: Verified');
    expect(markdown).toContain('Wrote file: src/main.ts');
    expect(markdown).toContain('Record ID: 22222222-2222-4222-8222-222222222222');
    expect(markdown).not.toContain('The model says everything passed.');
  });

  it('adds trusted restore acknowledgements without rewriting the original actions', () => {
    const report = buildTaskReport([]);
    const markdown = formatTaskReportMarkdown('Restore notes', report, [
      {
        protocol: 'accordlock.desktop.control/v2',
        schema_version: 2,
        session_id: 'session-1',
        recovery_id: '33333333-3333-4333-8333-333333333333',
        status: 'RESTORED',
        record: {
          restore_id: '44444444-4444-4444-8444-444444444444',
          record_hash: hash('e'),
          relative_path: 'notes.txt',
          content_sha256: hash('d'),
          completed_at: 1_725_000_100,
        },
      },
      {
        protocol: 'accordlock.desktop.control/v2',
        schema_version: 2,
        session_id: 'session-1',
        recovery_id: '55555555-5555-4555-8555-555555555555',
        status: 'CANCELLED',
        record: null,
      },
    ]);

    expect(markdown).toContain('Restore records: 2');
    expect(markdown).toContain('Restored file: notes.txt — Completed');
    expect(markdown).toContain('Restore ID: 44444444-4444-4444-8444-444444444444');
    expect(markdown).toContain(
      'Restore cancelled: 55555555-5555-4555-8555-555555555555 — No file was restored'
    );
  });
});
