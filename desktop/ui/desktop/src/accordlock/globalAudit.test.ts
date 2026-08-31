import { describe, expect, it, vi } from 'vitest';
import type { AccordLockSessionAuditEvent, AccordLockSessionAuditPage } from '../accordlockRuntime';
import type { AccordLockProject } from '../acp/projects';
import type { SessionListItem } from '../acp/sessions';
import {
  DEFAULT_GLOBAL_AUDIT_FILTERS,
  filterGlobalAuditRecords,
  formatGlobalAuditJson,
  formatGlobalAuditMarkdown,
  listAllGlobalAuditSessions,
  loadGlobalAuditDataset,
} from './globalAudit';

const hash = (character: string) => `sha256:${character.repeat(64)}`;
const reviewAssessment = (profile: 'PRE_EXECUTION' | 'COMPLETE_TRACE') => ({
  schema_version: 1 as const,
  profile,
  status: 'REVIEW_REQUIRED' as const,
  evidence_count: 0,
  finding_reasons: ['MISSING_EVIDENCE' as const],
});

function session(overrides: Partial<SessionListItem> = {}): SessionListItem {
  return {
    id: 'session-1',
    name: 'Release review',
    workingDir: 'C:\\Work\\Release',
    updatedAt: '2026-08-29T10:00:00Z',
    createdAt: '2026-08-29T09:00:00Z',
    messageCount: 4,
    projectId: 'public-release',
    ...overrides,
  };
}

function project(): AccordLockProject {
  return {
    id: 'public-release',
    title: 'Public release',
    description: '',
    instructions: '',
    workingDirs: ['C:\\Work\\Release'],
    archived: false,
    sourcePath: 'projects/public-release.md',
    writable: true,
    properties: { title: 'Public release', workingDirs: ['C:\\Work\\Release'] },
  };
}

function page(
  sessionId: string,
  events: AccordLockSessionAuditEvent[],
  overrides: Partial<AccordLockSessionAuditPage> = {}
): AccordLockSessionAuditPage {
  return {
    schema_version: 6,
    task_id: '11111111-1111-4111-8111-111111111111',
    session_id: sessionId,
    run_id: hash('a'),
    offset: 0,
    next_offset: null,
    total_events: events.length,
    snapshot_revision: 5,
    snapshot_at: 1_800_000_000,
    events,
    page_digest: hash('b'),
    ...overrides,
  };
}

function events(): AccordLockSessionAuditEvent[] {
  return [
    {
      event_id: 'access-1',
      recorded_at: 1_799_999_900,
      type: 'SESSION_APPROVED',
      task_id: '11111111-1111-4111-8111-111111111111',
      run_id: hash('a'),
      workspace_root: 'C:\\Work\\Release',
      policy_hash: hash('c'),
      expires_at: 1_800_003_600,
    },
    {
      event_id: 'start-1',
      recorded_at: 1_799_999_910,
      type: 'ACTION_STARTED',
      authorization_id: '22222222-2222-4222-8222-222222222222',
      tool_call_id: 'call-1',
      extension_id: 'developer',
      tool_name: 'write_file',
      proposal_digest: hash('d'),
      request_hash: hash('e'),
      conformance_evaluation_hashes: [hash('f')],
      task_scope_status: 'WITHIN_APPROVED_ACCESS',
      review_status: 'NOT_REQUIRED',
      decision_reason_code: 'POLICY_CONFORMANT',
      task_control_hash: hash('1'),
      task_control_provenance: 'DECISION_BOUND',
      intent_evaluation_hash: hash('3'),
      intent_assessment: reviewAssessment('PRE_EXECUTION'),
    },
    {
      event_id: 'complete-1',
      recorded_at: 1_799_999_920,
      type: 'ACTION_COMPLETED',
      authorization_id: '22222222-2222-4222-8222-222222222222',
      tool_call_id: 'call-1',
      outcome: 'FILE_WRITTEN',
      state: 'SUCCEEDED',
      record_hash: hash('f'),
      execution_lineage_hash: hash('a'),
      task_scope_status: 'WITHIN_APPROVED_ACCESS',
      review_status: 'NOT_REQUIRED',
      decision_reason_code: 'POLICY_CONFORMANT',
      task_control_hash: hash('2'),
      task_control_provenance: 'LINEAGE_BOUND',
      intent_pre_evaluation_hash: hash('3'),
      intent_complete_evaluation_hash: hash('4'),
      intent_pre_assessment: reviewAssessment('PRE_EXECUTION'),
      intent_complete_assessment: reviewAssessment('COMPLETE_TRACE'),
    },
    {
      event_id: 'denied-1',
      recorded_at: 1_799_900_000,
      type: 'ACTION_DENIED',
      denial_id: 1,
      attempted_run_id: hash('a'),
      tool_call_id: 'call-2',
      proposal_digest: hash('1'),
      reason_code: 'PATH_OUTSIDE_WORKSPACE',
    },
  ];
}

describe('listAllGlobalAuditSessions', () => {
  it('loads every task page and rejects a changing duplicate', async () => {
    const first = session();
    const second = session({ id: 'session-2', name: 'Second task' });
    const listSessions = vi
      .fn()
      .mockResolvedValueOnce({ sessions: [first], nextCursor: 'next' })
      .mockResolvedValueOnce({ sessions: [second], nextCursor: null });

    await expect(listAllGlobalAuditSessions(listSessions)).resolves.toEqual([first, second]);
    expect(listSessions).toHaveBeenNthCalledWith(1, undefined);
    expect(listSessions).toHaveBeenNthCalledWith(2, 'next');

    const changingList = vi
      .fn()
      .mockResolvedValueOnce({ sessions: [first], nextCursor: 'next' })
      .mockResolvedValueOnce({
        sessions: [{ ...first, name: 'Changed while loading' }],
        nextCursor: null,
      });
    await expect(listAllGlobalAuditSessions(changingList)).rejects.toThrow('task list changed');
  });
});

describe('loadGlobalAuditDataset', () => {
  it('aggregates protected task history and reports unreadable tasks without dropping results', async () => {
    const first = session();
    const second = session({
      id: 'session-2',
      name: 'Unprotected notes',
      projectId: undefined,
      workingDir: 'C:\\Work\\Notes',
    });
    const dataset = await loadGlobalAuditDataset({
      listProjects: async () => [project()],
      listSessions: async () => ({ sessions: [first, second], nextCursor: null }),
      nowSeconds: () => 1_800_000_000,
      readTaskAuditPages: async (sessionId) => {
        if (sessionId === first.id) return [page(first.id, events())];
        throw new Error('Task audit binding is unavailable');
      },
    });

    expect(dataset.taskBundles).toHaveLength(1);
    expect(dataset.records).toHaveLength(4);
    expect(dataset.records[0]).toMatchObject({
      title: 'Completed · write_file',
      projectName: 'Public release',
      taskName: 'Release review',
      status: 'VERIFIED',
    });
    expect(dataset.records.find((record) => record.event.type === 'ACTION_STARTED')?.status).toBe(
      'VERIFIED'
    );
    expect(dataset.readIssues).toEqual([
      expect.objectContaining({ code: 'NO_HISTORY', sessionId: 'session-2' }),
    ]);
  });

  it('keeps task history when project names fail to load', async () => {
    const dataset = await loadGlobalAuditDataset({
      listProjects: async () => {
        throw new Error('offline');
      },
      listSessions: async () => ({ sessions: [session()], nextCursor: null }),
      nowSeconds: () => 1_800_000_000,
      readTaskAuditPages: async (sessionId) => [page(sessionId, events())],
    });

    expect(dataset.projectCatalogAvailable).toBe(false);
    expect(dataset.records[0].projectName).toBe('Public release');
  });

  it('marks workspace-bound history separately from an unavailable audit service', async () => {
    const tasks = [session(), session({ id: 'session-2' })];
    const dataset = await loadGlobalAuditDataset({
      listProjects: async () => [],
      listSessions: async () => ({ sessions: tasks, nextCursor: null }),
      nowSeconds: () => 1_800_000_000,
      readTaskAuditPages: async (sessionId) => {
        throw new Error(
          sessionId === 'session-1'
            ? 'The task audit belongs to a different workspace'
            : 'Historical task audit database is unavailable'
        );
      },
    });

    expect(dataset.readIssues.map((issue) => issue.code)).toEqual([
      'OUTSIDE_WINDOW',
      'UNAVAILABLE',
    ]);
  });
});

describe('global audit filters and exports', () => {
  it('filters by search, status, project, task, and time', async () => {
    const dataset = await loadGlobalAuditDataset({
      listProjects: async () => [project()],
      listSessions: async () => ({ sessions: [session()], nextCursor: null }),
      nowSeconds: () => 1_800_000_000,
      readTaskAuditPages: async (sessionId) => [page(sessionId, events())],
    });

    expect(
      filterGlobalAuditRecords(
        dataset.records,
        {
          ...DEFAULT_GLOBAL_AUDIT_FILTERS,
          query: 'outside workspace',
          projectId: 'public-release',
          sessionId: 'session-1',
          status: 'BLOCKED',
          time: '7_DAYS',
        },
        1_800_000_000
      ).map((record) => record.event.type)
    ).toEqual(['ACTION_DENIED']);

    expect(
      filterGlobalAuditRecords(
        dataset.records,
        { ...DEFAULT_GLOBAL_AUDIT_FILTERS, time: '24_HOURS' },
        1_800_100_000
      )
    ).toHaveLength(0);
  });

  it('exports exact runtime pages in JSON and a readable consolidated report', async () => {
    const dataset = await loadGlobalAuditDataset({
      listProjects: async () => [project()],
      listSessions: async () => ({ sessions: [session()], nextCursor: null }),
      nowSeconds: () => 1_800_000_000,
      readTaskAuditPages: async (sessionId) => [page(sessionId, events())],
    });

    const json = JSON.parse(formatGlobalAuditJson(dataset));
    expect(json).toMatchObject({
      schemaVersion: 1,
      recordType: 'accordlock.global-audit-bundle',
      coverage: { sessionsFound: 1, protectedHistories: 1, recordedEvents: 4 },
    });
    expect(json.tasks[0].runtimePages[0].page_digest).toBe(hash('b'));

    const markdown = formatGlobalAuditMarkdown(dataset);
    expect(markdown).toContain('# AccordLock audit report');
    expect(markdown).toContain('— Completed · write\\_file');
    expect(markdown).toContain('- Task: Release review');
    expect(markdown).toContain('- Status: Blocked');
  });
});
