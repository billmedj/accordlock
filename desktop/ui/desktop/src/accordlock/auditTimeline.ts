import type { AccordLockTaskAuthorizationState } from './taskAuthorizationStore';
import type { AccordLockTaskRestoreAck } from './taskIpc';
import type { TaskExecutionEvidence, TaskReport } from './taskReport';
import type { TaskControlProjection } from './intentControl';

export type AuditHistoryScope = 'TASK_RECORDS_ONLY' | 'RUNTIME_LEDGER';
export type AuditEventStatus = 'INFO' | 'PENDING' | 'VERIFIED' | 'WARNING' | 'FAILED' | 'BLOCKED';
export type AuditEventCategory = 'REQUEST' | 'DECISION' | 'ACTIVITY' | 'CHANGE' | 'ISSUE';
export type AuditFilter = 'ALL' | 'DECISIONS' | 'CHANGES' | 'ISSUES';

export type AuditDetail = {
  label: string;
  value: string;
};

export type AuditDetailSection = {
  label: string;
  details: AuditDetail[];
};

export type TaskRestoreCapability = {
  contentHash: string;
  recordId: string;
  recoveryId: string;
  recoveryPath: string;
};

export type TaskRestoreRequest = TaskRestoreCapability & {
  target: string;
};

export type AuditReversibility =
  | { status: 'NOT_APPLICABLE'; label: 'No change'; explanation: string }
  | { status: 'NOT_SUPPORTED'; label: 'No restore point'; explanation: string }
  | { status: 'RECOVERY_COPY'; label: 'Recovery copy'; explanation: string }
  | { status: 'UNKNOWN'; label: 'Check first'; explanation: string }
  | {
      status: 'RESTORABLE';
      label: 'Restorable';
      explanation: string;
      request: TaskRestoreRequest;
    };

export type TaskAuditEventKind =
  | 'TASK_REQUESTED'
  | 'ACCESS_REVIEW_REQUESTED'
  | 'ACCESS_ACTIVE'
  | 'ACCESS_INACTIVE'
  | 'ACTION_APPROVAL_REQUESTED'
  | 'ACTION_DECISION_RECORDED'
  | 'ACTION_STARTED'
  | 'ACTION_DENIED'
  | 'ACTION_RECORDED'
  | 'FILE_RESTORE_PREPARED'
  | 'FILE_RESTORE_RECORDED'
  | 'VERIFICATION_INCOMPLETE'
  | 'ACCESS_REVOKED';

export type TaskAuditEvent = {
  category: AuditEventCategory;
  details: AuditDetailSection[];
  id: string;
  taskControl?: TaskControlProjection;
  kind: TaskAuditEventKind;
  reversibility: AuditReversibility | null;
  source: 'User' | 'Agent' | 'AccordLock';
  status: AuditEventStatus;
  summary: string;
  timestamp: number | null;
  title: string;
};

export type TaskRevocationEvidence = {
  reasonCode: string;
  recordedAt: number | null;
  requestId: string;
  revocationHash: string;
};

export type TaskAuditTimeline = {
  events: TaskAuditEvent[];
  historyScope: AuditHistoryScope;
  issueCount: number;
  reversibleCount: number;
  scopeNotice: string;
  verifiedActionCount: number;
};

export type BuildTaskAuditTimelineInput = {
  authorization: AccordLockTaskAuthorizationState;
  expiresAt: number | null;
  historyScope: AuditHistoryScope;
  objective: string;
  pendingDecision: boolean;
  report: TaskReport;
  requestedAt: number | null;
  restoreAcknowledgements: readonly AccordLockTaskRestoreAck[];
  restoreCapabilities: readonly TaskRestoreCapability[];
  revocation: TaskRevocationEvidence | null;
  sessionId: string;
  workspace: string;
};

const MUTATING_OPERATIONS = new Set(['DELETE', 'EDIT', 'RUN', 'WRITE']);

function operationTitle(operation: string): string {
  const titles: Readonly<Record<string, string>> = {
    DELETE: 'Moved file to recovery',
    EDIT: 'Edited file',
    READ: 'Read file',
    RUN: 'Ran program',
    TREE: 'Browsed folder',
    WRITE: 'Wrote file',
  };
  return titles[operation] ?? 'Recorded action';
}

function executionStatus(evidence: TaskExecutionEvidence): AuditEventStatus {
  if (evidence.reasonCode.includes('UNKNOWN')) return 'WARNING';
  return evidence.outcome === 'SUCCEEDED' ? 'VERIFIED' : 'FAILED';
}

function executionSummary(evidence: TaskExecutionEvidence): string {
  if (evidence.reasonCode.includes('UNKNOWN')) return 'The result could not be confirmed.';
  return evidence.outcome === 'SUCCEEDED' ? 'Completed and recorded.' : 'Failed and recorded.';
}

function matchingRestoreCapability(
  evidence: TaskExecutionEvidence,
  capabilities: readonly TaskRestoreCapability[]
): TaskRestoreCapability | null {
  if (!evidence.recovery) return null;
  return (
    capabilities.find(
      (capability) =>
        capability.recordId === evidence.recordId &&
        capability.recoveryId === evidence.recovery?.recoveryId &&
        capability.recoveryPath === evidence.recovery.recoveryPath &&
        capability.contentHash === evidence.recovery.contentHash
    ) ?? null
  );
}

function reversibilityFor(
  evidence: TaskExecutionEvidence,
  capabilities: readonly TaskRestoreCapability[]
): AuditReversibility {
  if (evidence.outcome !== 'SUCCEEDED' || evidence.reasonCode.includes('UNKNOWN')) {
    return {
      status: 'UNKNOWN',
      label: 'Check first',
      explanation: 'Check the file or system state before trying to restore it.',
    };
  }
  if (evidence.operation === 'READ' || evidence.operation === 'TREE') {
    return {
      status: 'NOT_APPLICABLE',
      label: 'No change',
      explanation: 'This action did not change the folder.',
    };
  }
  if (evidence.operation === 'DELETE' && evidence.recovery) {
    const capability = matchingRestoreCapability(evidence, capabilities);
    if (capability) {
      return {
        status: 'RESTORABLE',
        label: 'Restorable',
        explanation: 'This file can be restored from its saved copy.',
        request: { ...capability, target: evidence.target },
      };
    }
    return {
      status: 'RECOVERY_COPY',
      label: 'Recovery copy',
      explanation: 'The file was saved, but automatic restore is unavailable.',
    };
  }
  return {
    status: 'NOT_SUPPORTED',
    label: 'No restore point',
    explanation:
      evidence.operation === 'RUN'
        ? 'Program effects may extend beyond this folder.'
        : 'No earlier copy of this file is available.',
  };
}

function actionDetails(evidence: TaskExecutionEvidence): AuditDetailSection[] {
  const effectDetails: AuditDetail[] = [
    { label: 'Operation', value: evidence.operation },
    { label: 'Target', value: evidence.target },
  ];
  if (evidence.resultHash) effectDetails.push({ label: 'Result hash', value: evidence.resultHash });
  if (evidence.recovery) {
    effectDetails.push(
      { label: 'Recovery ID', value: evidence.recovery.recoveryId },
      { label: 'Recovery path', value: evidence.recovery.recoveryPath },
      { label: 'Recovered content hash', value: evidence.recovery.contentHash }
    );
  }
  return [
    {
      label: 'Request',
      details: [{ label: 'Request hash', value: evidence.requestHash }],
    },
    {
      label: 'Authorization',
      details: [{ label: 'Authorization ID', value: evidence.authorizationId }],
    },
    { label: 'Effect', details: effectDetails },
    {
      label: 'Outcome',
      details: [
        { label: 'Reason code', value: evidence.reasonCode },
        { label: 'Record ID', value: evidence.recordId },
        { label: 'Verification hash', value: evidence.recordHash },
      ],
    },
  ];
}

function taskRequestEvent(input: BuildTaskAuditTimelineInput): TaskAuditEvent {
  return {
    category: 'REQUEST',
    details: [
      {
        label: 'Task',
        details: [
          { label: 'Objective', value: input.objective.trim() || 'Untitled task' },
          { label: 'Folder', value: input.workspace },
          { label: 'Session ID', value: input.sessionId },
        ],
      },
    ],
    id: `task:${input.sessionId}:requested`,
    kind: 'TASK_REQUESTED',
    reversibility: null,
    source: 'User',
    status: 'INFO',
    summary: 'The outcome and folder were recorded.',
    timestamp: input.requestedAt,
    title: 'Task requested',
  };
}

function accessEvent(input: BuildTaskAuditTimelineInput): TaskAuditEvent {
  if (input.authorization === 'PENDING') {
    return {
      category: 'DECISION',
      details: [{ label: 'Access', details: [{ label: 'State', value: 'Waiting for approval' }] }],
      id: `task:${input.sessionId}:access-review`,
      kind: 'ACCESS_REVIEW_REQUESTED',
      reversibility: null,
      source: 'AccordLock',
      status: 'PENDING',
      summary: 'Review task access to begin.',
      timestamp: null,
      title: 'Access review requested',
    };
  }
  if (input.authorization === 'APPROVED') {
    const details: AuditDetail[] = [{ label: 'State', value: 'Active' }];
    if (input.expiresAt !== null) {
      details.push({
        label: 'Access ends',
        value: new Date(input.expiresAt * 1_000).toISOString(),
      });
    }
    return {
      category: 'DECISION',
      details: [{ label: 'Access', details }],
      id: `task:${input.sessionId}:access-active`,
      kind: 'ACCESS_ACTIVE',
      reversibility: null,
      source: 'AccordLock',
      status: 'VERIFIED',
      summary: 'Actions follow the approved task limits.',
      timestamp: null,
      title: 'Task access approved',
    };
  }
  return {
    category: 'DECISION',
    details: [{ label: 'Access', details: [{ label: 'State', value: 'Inactive' }] }],
    id: `task:${input.sessionId}:access-inactive`,
    kind: 'ACCESS_INACTIVE',
    reversibility: null,
    source: 'AccordLock',
    status: 'BLOCKED',
    summary: 'Actions remain blocked.',
    timestamp: null,
    title: 'Task access inactive',
  };
}

function pendingApprovalEvent(sessionId: string): TaskAuditEvent {
  return {
    category: 'DECISION',
    details: [{ label: 'Decision', details: [{ label: 'State', value: 'Waiting for approval' }] }],
    id: `task:${sessionId}:pending-action-approval`,
    kind: 'ACTION_APPROVAL_REQUESTED',
    reversibility: null,
    source: 'AccordLock',
    status: 'PENDING',
    summary: 'Review the requested action before it can run.',
    timestamp: null,
    title: 'Action approval needed',
  };
}

function actionEvent(
  evidence: TaskExecutionEvidence,
  capabilities: readonly TaskRestoreCapability[]
): TaskAuditEvent {
  return {
    category: MUTATING_OPERATIONS.has(evidence.operation) ? 'CHANGE' : 'ACTIVITY',
    details: actionDetails(evidence),
    id: `execution:${evidence.recordId}`,
    kind: 'ACTION_RECORDED',
    reversibility: reversibilityFor(evidence, capabilities),
    source: 'AccordLock',
    status: executionStatus(evidence),
    summary: executionSummary(evidence),
    timestamp: evidence.recordedAt,
    title: `${operationTitle(evidence.operation)} · ${evidence.target}`,
  };
}

function restoreEvent(acknowledgement: AccordLockTaskRestoreAck, index: number): TaskAuditEvent {
  if (acknowledgement.status === 'CANCELLED') {
    return {
      category: 'DECISION',
      details: [
        {
          label: 'Restore',
          details: [
            { label: 'Recovery ID', value: acknowledgement.recovery_id },
            { label: 'Status', value: acknowledgement.status },
          ],
        },
      ],
      id: `restore:${acknowledgement.recovery_id}:cancelled:${index}`,
      kind: 'FILE_RESTORE_RECORDED',
      reversibility: null,
      source: 'User',
      status: 'INFO',
      summary: 'No file was restored.',
      timestamp: null,
      title: 'Restore cancelled',
    };
  }

  const record = acknowledgement.record;
  const alreadyRestored = acknowledgement.status === 'ALREADY_RESTORED';
  return {
    category: 'CHANGE',
    details: [
      {
        label: 'Restore',
        details: [
          { label: 'Status', value: acknowledgement.status },
          { label: 'Recovery ID', value: acknowledgement.recovery_id },
          { label: 'Restore ID', value: record.restore_id },
          { label: 'File', value: record.relative_path },
          { label: 'Content hash', value: record.content_sha256 },
          { label: 'Record hash', value: record.record_hash },
        ],
      },
    ],
    id: `restore:${record.restore_id}:${index}`,
    kind: 'FILE_RESTORE_RECORDED',
    reversibility: null,
    source: 'AccordLock',
    status: alreadyRestored ? 'INFO' : 'VERIFIED',
    summary: alreadyRestored
      ? 'No new change was made.'
      : 'The original path now contains the saved copy.',
    timestamp: record.completed_at,
    title: `${alreadyRestored ? 'File already restored' : 'Restored file'} · ${record.relative_path}`,
  };
}

function incompleteVerificationEvent(sessionId: string, count: number): TaskAuditEvent {
  return {
    category: 'ISSUE',
    details: [
      {
        label: 'Verification',
        details: [{ label: 'Unverified actions', value: String(count) }],
      },
    ],
    id: `task:${sessionId}:verification-incomplete`,
    kind: 'VERIFICATION_INCOMPLETE',
    reversibility: {
      status: 'UNKNOWN',
      label: 'Check first',
      explanation: 'Check the file or system state before retrying or restoring it.',
    },
    source: 'AccordLock',
    status: 'WARNING',
    summary: `${count} ${count === 1 ? 'action could' : 'actions could'} not be verified.`,
    timestamp: null,
    title: 'Verification incomplete',
  };
}

function revocationEvent(sessionId: string, revocation: TaskRevocationEvidence): TaskAuditEvent {
  return {
    category: 'DECISION',
    details: [
      {
        label: 'Revocation',
        details: [
          { label: 'Reason code', value: revocation.reasonCode },
          { label: 'Request ID', value: revocation.requestId },
          { label: 'Revocation hash', value: revocation.revocationHash },
        ],
      },
    ],
    id: `task:${sessionId}:revoked:${revocation.requestId}`,
    kind: 'ACCESS_REVOKED',
    reversibility: null,
    source: 'AccordLock',
    status: 'BLOCKED',
    summary: 'Future actions are blocked. Earlier effects are unchanged.',
    timestamp: revocation.recordedAt,
    title: 'Task access revoked',
  };
}

export function buildTaskAuditTimeline(input: BuildTaskAuditTimelineInput): TaskAuditTimeline {
  const events = [taskRequestEvent(input), accessEvent(input)];
  if (input.pendingDecision) events.push(pendingApprovalEvent(input.sessionId));
  events.push(
    ...input.report.evidence.map((evidence) => actionEvent(evidence, input.restoreCapabilities))
  );
  events.push(
    ...input.restoreAcknowledgements.map((acknowledgement, index) =>
      restoreEvent(acknowledgement, index)
    )
  );
  if (input.report.unverifiedActions > 0) {
    events.push(incompleteVerificationEvent(input.sessionId, input.report.unverifiedActions));
  }
  if (input.revocation) events.push(revocationEvent(input.sessionId, input.revocation));

  const restoredRecoveryIds = new Set(
    input.restoreAcknowledgements
      .filter((acknowledgement) => acknowledgement.status !== 'CANCELLED')
      .map((acknowledgement) => acknowledgement.recovery_id)
  );

  return {
    events,
    historyScope: input.historyScope,
    issueCount: events.filter((event) => ['BLOCKED', 'FAILED', 'WARNING'].includes(event.status))
      .length,
    reversibleCount: events.filter(
      (event) =>
        event.reversibility?.status === 'RESTORABLE' &&
        !restoredRecoveryIds.has(event.reversibility.request.recoveryId)
    ).length,
    scopeNotice:
      input.historyScope === 'RUNTIME_LEDGER'
        ? 'Verified against the execution log.'
        : 'Saved task activity. Earlier records may be unavailable.',
    verifiedActionCount: input.report.evidence.length,
  };
}

export function filterTaskAuditEvents(
  events: readonly TaskAuditEvent[],
  filter: AuditFilter
): TaskAuditEvent[] {
  if (filter === 'ALL') return [...events];
  if (filter === 'DECISIONS') return events.filter((event) => event.category === 'DECISION');
  if (filter === 'CHANGES') return events.filter((event) => event.category === 'CHANGE');
  return events.filter((event) => ['BLOCKED', 'FAILED', 'WARNING'].includes(event.status));
}

export function formatTaskAuditExport(timeline: TaskAuditTimeline): string {
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      recordType: 'accordlock.task-audit-projection',
      historyScope: timeline.historyScope,
      events: timeline.events,
    },
    null,
    2
  )}\n`;
}
