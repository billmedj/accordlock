import { describe, expect, it } from 'vitest';
import type { AccordLockSessionAuditPage } from '../accordlockRuntime';
import type { TaskAuditTimeline } from './auditTimeline';
import {
  formatRuntimeTaskAuditExport,
  mergeRuntimeAuditPage,
  parseAccordLockTaskAuditAck,
} from './runtimeAudit';

const taskId = '11111111-1111-4111-8111-111111111111';
const authorizationId = '22222222-2222-4222-8222-222222222222';
const digest = (character: string) => `sha256:${character.repeat(64)}`;
const reviewAssessment = (profile: 'PRE_EXECUTION' | 'COMPLETE_TRACE') => ({
  schema_version: 1 as const,
  profile,
  status: 'REVIEW_REQUIRED' as const,
  evidence_count: 0,
  finding_reasons: ['MISSING_EVIDENCE' as const],
});

const page: AccordLockSessionAuditPage = {
  schema_version: 6,
  task_id: taskId,
  session_id: 'session-1',
  run_id: 'run-1',
  offset: 0,
  next_offset: null,
  total_events: 3,
  snapshot_revision: 17,
  snapshot_at: 30,
  events: [
    {
      type: 'ACTION_COMPLETED',
      event_id: 'completed',
      recorded_at: 30,
      authorization_id: authorizationId,
      tool_call_id: 'call-1',
      outcome: 'SUCCEEDED',
      state: 'SUCCEEDED',
      record_hash: digest('a'),
      execution_lineage_hash: digest('b'),
      task_scope_status: 'WITHIN_APPROVED_ACCESS',
      review_status: 'NOT_REQUIRED',
      decision_reason_code: 'POLICY_CONFORMANT',
      task_control_hash: digest('f'),
      task_control_provenance: 'LINEAGE_BOUND',
      intent_pre_evaluation_hash: digest('1'),
      intent_complete_evaluation_hash: digest('2'),
      intent_pre_assessment: reviewAssessment('PRE_EXECUTION'),
      intent_complete_assessment: reviewAssessment('COMPLETE_TRACE'),
    },
    {
      type: 'ACTION_STARTED',
      event_id: 'started',
      recorded_at: 20,
      authorization_id: authorizationId,
      tool_call_id: 'call-1',
      extension_id: 'developer',
      tool_name: 'write',
      proposal_digest: digest('b'),
      request_hash: digest('c'),
      conformance_evaluation_hashes: [digest('d')],
      task_scope_status: 'WITHIN_APPROVED_ACCESS',
      review_status: 'NOT_REQUIRED',
      decision_reason_code: 'POLICY_CONFORMANT',
      task_control_hash: digest('f'),
      task_control_provenance: 'DECISION_BOUND',
      intent_evaluation_hash: digest('1'),
      intent_assessment: reviewAssessment('PRE_EXECUTION'),
    },
    {
      type: 'ACTION_DENIED',
      event_id: 'denied',
      recorded_at: 10,
      denial_id: 1,
      attempted_run_id: 'attempted-run-2',
      tool_call_id: 'call-2',
      proposal_digest: digest('d'),
      reason_code: 'POLICY_DENIED',
    },
  ],
  page_digest: digest('e'),
};

const timeline: TaskAuditTimeline = {
  events: [],
  historyScope: 'TASK_RECORDS_ONLY',
  issueCount: 0,
  reversibleCount: 0,
  scopeNotice: 'Local records only.',
  verifiedActionCount: 0,
};

describe('runtime audit renderer boundary', () => {
  it('accepts only a strict page bound to the request', () => {
    const acknowledgement = {
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      page,
    };
    expect(parseAccordLockTaskAuditAck(acknowledgement, 'session-1', 0, 100).page).toStrictEqual(
      page
    );
    expect(() =>
      parseAccordLockTaskAuditAck({ ...acknowledgement, extra: true }, 'session-1', 0, 100)
    ).toThrow();
    expect(() =>
      parseAccordLockTaskAuditAck(
        { ...acknowledgement, page: { ...page, next_offset: 2 } },
        'session-1',
        0,
        100
      )
    ).toThrow('does not match the request');
  });

  it('pairs execution records, surfaces denials, and never invents raw action data', () => {
    const merged = mergeRuntimeAuditPage(timeline, page);
    expect(merged.historyScope).toBe('RUNTIME_LEDGER');
    expect(merged.events.filter((event) => event.kind === 'ACTION_RECORDED')).toHaveLength(1);
    const denial = merged.events.find((event) => event.kind === 'ACTION_DENIED');
    expect(denial).toMatchObject({
      title: 'Blocked',
      summary: 'The runtime blocked this action.',
    });
    const completed = merged.events.find((event) => event.kind === 'ACTION_RECORDED');
    expect(completed).toMatchObject({
      taskControl: {
        label: 'Within approved access',
        reason: 'The action stayed within the approved access.',
        provenance: 'LINEAGE_BOUND',
      },
      summary: 'The action stayed within the approved access.',
    });
    expect(JSON.stringify(completed?.details)).toContain(digest('f'));
    expect(JSON.stringify(completed?.details)).toContain('Task check (before)');
    expect(JSON.stringify(completed?.details)).toContain('No qualified evidence was available.');
    expect(JSON.stringify(completed?.details)).not.toContain('Intent review required');
    expect(JSON.stringify(denial?.details)).toContain('attempted-run-2');
    expect(JSON.stringify(merged)).not.toMatch(/arguments|terminal output|file contents/iu);
  });

  it('rejects unknown or inconsistent completed-action task controls', () => {
    const acknowledgement = {
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      page,
    };
    const completed = page.events[0];
    expect(completed?.type).toBe('ACTION_COMPLETED');
    expect(() =>
      parseAccordLockTaskAuditAck(
        {
          ...acknowledgement,
          page: {
            ...page,
            events: [{ ...completed, task_scope_status: 'UNKNOWN' }, ...page.events.slice(1)],
          },
        },
        'session-1',
        0
      )
    ).toThrow();
    expect(() =>
      parseAccordLockTaskAuditAck(
        {
          ...acknowledgement,
          page: {
            ...page,
            events: [{ ...completed, review_status: 'APPROVED' }, ...page.events.slice(1)],
          },
        },
        'session-1',
        0
      )
    ).toThrow('action task control is inconsistent');
  });

  it('never treats an assessment without qualified evidence as verified', () => {
    const acknowledgement = {
      protocol: 'accordlock.desktop.control/v2',
      schema_version: 2,
      session_id: 'session-1',
      page,
    };
    const completed = page.events[0];
    expect(completed?.type).toBe('ACTION_COMPLETED');
    if (completed?.type !== 'ACTION_COMPLETED') throw new Error('completed fixture is missing');

    expect(() =>
      parseAccordLockTaskAuditAck(
        {
          ...acknowledgement,
          page: {
            ...page,
            events: [
              {
                ...completed,
                intent_pre_assessment: {
                  ...completed.intent_pre_assessment,
                  status: 'VERIFIED',
                  evidence_count: 0,
                  finding_reasons: ['SUPPORTED'],
                },
              },
              ...page.events.slice(1),
            ],
          },
        },
        'session-1',
        0
      )
    ).toThrow('intent assessment is inconsistent');
  });

  it('exports verified pages with their digests and the readable projection', () => {
    const merged = mergeRuntimeAuditPage(timeline, page);
    const exported = JSON.parse(formatRuntimeTaskAuditExport(merged, [page]));
    expect(exported).toMatchObject({
      schemaVersion: 2,
      recordType: 'accordlock.task-audit-bundle',
      historyScope: 'RUNTIME_LEDGER',
      snapshot: { sessionId: 'session-1', snapshotRevision: 17, totalEvents: 3 },
    });
    expect(exported.runtimePages[0].page_digest).toBe(digest('e'));
    expect(exported.projection.events).toHaveLength(2);
  });
});
