import { z } from 'zod';
import type {
  AccordLockIntentAssessment,
  AccordLockSessionAuditEvent,
  AccordLockSessionAuditPage,
} from '../accordlockRuntime';
import { ACCORDLOCK_CONTROL_PROTOCOL, type AccordLockTaskAuditAck } from './taskIpc';
import type { AuditDetailSection, TaskAuditEvent, TaskAuditTimeline } from './auditTimeline';
import { projectCompletedTaskControl, projectDeniedTaskControl } from './intentControl';

const canonicalUuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/u)
  .refine((value) => value !== `sha256:${'0'.repeat(64)}`, 'must not be the zero digest');
const bounded = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        value.trim() === value &&
        // Protocol text must not carry hidden controls or bidirectional overrides into the UI.
        // eslint-disable-next-line no-control-regex
        !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value),
      'must be canonical display text'
    );
const relativePath = bounded(4_096).refine(
  (value) =>
    !value.startsWith('/') &&
    !value.startsWith('\\') &&
    !value.includes('\\') &&
    !value.includes(':') &&
    value
      .split('/')
      .every((component) => component.length > 0 && component !== '.' && component !== '..'),
  'must be a canonical relative path'
);
const eventBase = {
  event_id: bounded(512),
  recorded_at: z.number().int().nonnegative().safe(),
};
const intentFindingReason = z.enum([
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
]);
const intentAssessmentSchema = z
  .object({
    schema_version: z.literal(1),
    profile: z.enum(['PRE_EXECUTION', 'COMPLETE_TRACE']),
    status: z.enum(['VERIFIED', 'REVIEW_REQUIRED', 'BLOCKED']),
    evidence_count: z.number().int().nonnegative().max(65_535).safe(),
    finding_reasons: z.array(intentFindingReason).max(12),
  })
  .strict()
  .superRefine((assessment, context) => {
    const findings = assessment.finding_reasons;
    const unique = new Set(findings).size === findings.length;
    const verified =
      assessment.status === 'VERIFIED' &&
      assessment.evidence_count > 0 &&
      findings.length > 0 &&
      findings.every((reason) => reason === 'SUPPORTED');
    const review =
      assessment.status === 'REVIEW_REQUIRED' &&
      findings.some((reason) =>
        [
          'MISSING_EVIDENCE',
          'INCONCLUSIVE_EVIDENCE',
          'UNVERIFIED_PROVENANCE',
          'EXPIRED_CALIBRATION',
          'CONFIDENCE_THRESHOLD_UNCERTAIN',
        ].includes(reason)
      );
    const blocked =
      assessment.status === 'BLOCKED' &&
      findings.some((reason) =>
        [
          'BELOW_THRESHOLD',
          'CONTRADICTORY_EVIDENCE',
          'SCOPE_MISMATCH',
          'EVIDENCE_CHAIN_MISMATCH',
          'LEDGER_SNAPSHOT_MISMATCH',
          'TRUST_POLICY_MISMATCH',
        ].includes(reason)
      );
    if (!unique || (!verified && !review && !blocked)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'intent assessment is inconsistent',
      });
    }
  });
const auditEventSchema = z
  .discriminatedUnion('type', [
    z
      .object({
        ...eventBase,
        type: z.literal('SESSION_APPROVED'),
        task_id: canonicalUuid,
        run_id: bounded(256),
        workspace_root: bounded(4_096),
        policy_hash: digest,
        expires_at: z.number().int().positive().safe(),
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('SESSION_REVOKED'),
        task_id: canonicalUuid,
        run_id: bounded(256),
        revocation_digest: digest,
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('ACTION_DECISION'),
        approval_id: canonicalUuid,
        tool_call_id: bounded(256),
        proposal_digest: digest,
        decision: z.enum(['APPROVED', 'DENIED']),
        evidence_hash: digest,
        consumed: z.boolean(),
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('ACTION_STARTED'),
        authorization_id: canonicalUuid,
        tool_call_id: bounded(256),
        extension_id: bounded(256),
        tool_name: bounded(256),
        proposal_digest: digest,
        request_hash: digest,
        conformance_evaluation_hashes: z.array(digest).max(16),
        task_scope_status: z.enum(['WITHIN_APPROVED_ACCESS', 'REVIEW_REQUIRED']),
        review_status: z.enum(['NOT_REQUIRED', 'APPROVED']),
        decision_reason_code: z.enum(['POLICY_CONFORMANT', 'ACTION_APPROVAL_ACCEPTED']),
        task_control_hash: digest,
        task_control_provenance: z.literal('DECISION_BOUND'),
        intent_evaluation_hash: digest,
        intent_assessment: intentAssessmentSchema,
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('ACTION_COMPLETED'),
        authorization_id: canonicalUuid,
        tool_call_id: bounded(256),
        outcome: bounded(64),
        state: z.enum(['SUCCEEDED', 'EXECUTION_UNKNOWN']),
        record_hash: digest.nullable(),
        execution_lineage_hash: digest,
        task_scope_status: z.enum(['WITHIN_APPROVED_ACCESS', 'REVIEW_REQUIRED']),
        review_status: z.enum(['NOT_REQUIRED', 'APPROVED']),
        decision_reason_code: z.enum(['POLICY_CONFORMANT', 'ACTION_APPROVAL_ACCEPTED']),
        task_control_hash: digest,
        task_control_provenance: z.enum(['LINEAGE_BOUND', 'EMBEDDED', 'RECONSTRUCTED']),
        intent_pre_evaluation_hash: digest,
        intent_complete_evaluation_hash: digest.nullable(),
        intent_pre_assessment: intentAssessmentSchema,
        intent_complete_assessment: intentAssessmentSchema,
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('ACTION_DENIED'),
        denial_id: z.number().int().positive().safe(),
        attempted_run_id: bounded(256),
        tool_call_id: bounded(256),
        proposal_digest: digest,
        reason_code: bounded(128),
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('RESTORE_PREPARED'),
        restore_id: canonicalUuid,
        recovery_id: canonicalUuid,
        relative_path: relativePath,
        content_hash: digest,
      })
      .strict(),
    z
      .object({
        ...eventBase,
        type: z.literal('RESTORE_COMPLETED'),
        restore_id: canonicalUuid,
        recovery_id: canonicalUuid,
        relative_path: relativePath,
        record_hash: digest,
      })
      .strict(),
  ])
  .superRefine((event, context) => {
    if (event.type !== 'ACTION_STARTED' && event.type !== 'ACTION_COMPLETED') return;
    const automatic =
      event.task_scope_status === 'WITHIN_APPROVED_ACCESS' &&
      event.review_status === 'NOT_REQUIRED' &&
      event.decision_reason_code === 'POLICY_CONFORMANT';
    const reviewed =
      event.task_scope_status === 'REVIEW_REQUIRED' &&
      event.review_status === 'APPROVED' &&
      event.decision_reason_code === 'ACTION_APPROVAL_ACCEPTED';
    const conformanceIsValid =
      event.type === 'ACTION_COMPLETED' ||
      (automatic
        ? event.conformance_evaluation_hashes.length > 0 &&
          event.conformance_evaluation_hashes.every(
            (hash, index, hashes) => index === 0 || hashes[index - 1] < hash
          )
        : event.conformance_evaluation_hashes.length === 0);
    const profilesAreValid =
      event.type === 'ACTION_STARTED'
        ? event.intent_assessment.profile === 'PRE_EXECUTION'
        : event.intent_pre_assessment.profile === 'PRE_EXECUTION' &&
          event.intent_complete_assessment.profile === 'COMPLETE_TRACE';
    const valid = (automatic || reviewed) && conformanceIsValid && profilesAreValid;
    if (!valid) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'action task control is inconsistent',
      });
    }
  });

const auditPageSchema = z
  .object({
    schema_version: z.literal(6),
    task_id: canonicalUuid,
    session_id: bounded(256),
    run_id: bounded(256),
    offset: z.number().int().nonnegative().max(100_000).safe(),
    next_offset: z.number().int().positive().max(100_000).safe().nullable(),
    total_events: z.number().int().positive().max(100_000).safe(),
    snapshot_revision: z.number().int().nonnegative().safe(),
    snapshot_at: z.number().int().nonnegative().safe(),
    events: z.array(auditEventSchema).max(100),
    page_digest: digest,
  })
  .strict();

const taskAuditAckSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    session_id: bounded(256),
    page: auditPageSchema,
  })
  .strict();

export function parseAccordLockTaskAuditAck(
  value: unknown,
  expectedSessionId: string,
  expectedOffset: number,
  expectedLimit = 100,
  expectedSnapshotRevision: number | null = null
): AccordLockTaskAuditAck {
  const acknowledgement = taskAuditAckSchema.parse(value) as AccordLockTaskAuditAck;
  const pageEnd = acknowledgement.page.offset + acknowledgement.page.events.length;
  if (
    expectedSnapshotRevision !== null &&
    acknowledgement.page.snapshot_revision !== expectedSnapshotRevision
  ) {
    throw new Error('AccordLock audit changed while it was being exported');
  }
  if (
    acknowledgement.session_id !== expectedSessionId ||
    acknowledgement.page.session_id !== expectedSessionId ||
    acknowledgement.page.offset !== expectedOffset ||
    acknowledgement.page.events.length > expectedLimit ||
    (acknowledgement.page.next_offset !== null &&
      (acknowledgement.page.events.length === 0 ||
        acknowledgement.page.next_offset !== pageEnd ||
        pageEnd >= acknowledgement.page.total_events)) ||
    (acknowledgement.page.next_offset === null && pageEnd < acknowledgement.page.total_events)
  ) {
    throw new Error('AccordLock audit page does not match the request');
  }
  return acknowledgement;
}

function details(label: string, values: Array<[string, string]>): AuditDetailSection[] {
  return [{ label, details: values.map(([name, value]) => ({ label: name, value })) }];
}

function intentAssessmentCopy(assessment: AccordLockIntentAssessment): {
  label: string;
  reason: string;
} {
  if (assessment.status === 'VERIFIED') {
    return {
      label: 'Verified',
      reason: 'Qualified evidence matched the declared task constraints.',
    };
  }
  if (assessment.status === 'BLOCKED') {
    return {
      label: 'Blocked',
      reason: 'Evidence contradicted the task constraints or failed validation.',
    };
  }
  if (assessment.finding_reasons.includes('MISSING_EVIDENCE')) {
    return { label: 'Not verified', reason: 'No qualified evidence was available.' };
  }
  if (assessment.finding_reasons.includes('UNVERIFIED_PROVENANCE')) {
    return { label: 'Not verified', reason: 'The evidence source was not trusted for this task.' };
  }
  if (assessment.finding_reasons.includes('EXPIRED_CALIBRATION')) {
    return { label: 'Not verified', reason: 'The evidence calibration had expired.' };
  }
  return { label: 'Not verified', reason: 'The available evidence was inconclusive.' };
}

function baseDetailValues(timeline: TaskAuditTimeline, label: string): Set<string> {
  return new Set(
    timeline.events.flatMap((event) =>
      event.details.flatMap((section) =>
        section.details.filter((detail) => detail.label === label).map((detail) => detail.value)
      )
    )
  );
}

function eventFromLedger(
  event: AccordLockSessionAuditEvent,
  completedByAuthorization: ReadonlyMap<
    string,
    Extract<AccordLockSessionAuditEvent, { type: 'ACTION_COMPLETED' }>
  >,
  completedRestoreIds: ReadonlySet<string>,
  startedAuthorizationIds: ReadonlySet<string>,
  recordedAuthorizationIds: ReadonlySet<string>,
  recordedRestoreIds: ReadonlySet<string>
): TaskAuditEvent | null {
  const base = {
    id: `ledger:${event.event_id}`,
    reversibility: null,
    source: 'AccordLock' as const,
    timestamp: event.recorded_at,
  };
  switch (event.type) {
    case 'SESSION_APPROVED':
      return {
        ...base,
        category: 'DECISION',
        kind: 'ACCESS_ACTIVE',
        status: 'VERIFIED',
        title: 'Task access approved',
        summary: `Active until ${new Date(event.expires_at * 1_000).toLocaleString()}.`,
        details: details('Access', [
          ['Policy hash', event.policy_hash],
          ['Run ID', event.run_id],
        ]),
      };
    case 'SESSION_REVOKED':
      return {
        ...base,
        category: 'DECISION',
        kind: 'ACCESS_REVOKED',
        status: 'BLOCKED',
        title: 'Task access revoked',
        summary: 'Further actions are blocked.',
        details: details('Revocation', [
          ['Run ID', event.run_id],
          ['Revocation hash', event.revocation_digest],
        ]),
      };
    case 'ACTION_DECISION':
      return {
        ...base,
        category: 'DECISION',
        kind: 'ACTION_DECISION_RECORDED',
        status: event.decision === 'APPROVED' ? 'VERIFIED' : 'BLOCKED',
        title: event.decision === 'APPROVED' ? 'Action approved' : 'Action denied',
        summary: event.consumed ? 'The decision was used once.' : 'The decision was recorded.',
        details: details('Decision', [
          ['Tool call', event.tool_call_id],
          ['Proposal hash', event.proposal_digest],
          ['Evidence hash', event.evidence_hash],
        ]),
      };
    case 'ACTION_DENIED': {
      const taskControl = projectDeniedTaskControl(event.reason_code);
      return {
        ...base,
        category: 'ISSUE',
        taskControl,
        kind: 'ACTION_DENIED',
        status: 'BLOCKED',
        title: taskControl.label,
        summary: taskControl.reason,
        details: details('Decision', [
          ['Reason code', event.reason_code],
          ['Attempted run', event.attempted_run_id],
          ['Tool call', event.tool_call_id],
          ['Proposal hash', event.proposal_digest],
        ]),
      };
    }
    case 'ACTION_STARTED': {
      if (recordedAuthorizationIds.has(event.authorization_id)) return null;
      const completed = completedByAuthorization.get(event.authorization_id);
      const uncertain = completed?.state === 'EXECUTION_UNKNOWN';
      const taskControl = projectCompletedTaskControl(completed ?? event);
      const preAssessment = intentAssessmentCopy(
        completed?.intent_pre_assessment ?? event.intent_assessment
      );
      const completeAssessment = completed
        ? intentAssessmentCopy(completed.intent_complete_assessment)
        : null;
      return {
        ...base,
        timestamp: completed?.recorded_at ?? event.recorded_at,
        category: 'ACTIVITY',
        taskControl,
        kind: completed ? 'ACTION_RECORDED' : 'ACTION_STARTED',
        status: completed ? (uncertain ? 'WARNING' : 'VERIFIED') : 'PENDING',
        title: `${completed ? (uncertain ? 'Check result' : 'Action completed') : 'Action started'} · ${event.tool_name}`,
        summary: completed
          ? uncertain
            ? `${taskControl!.reason} The final state could not be confirmed.`
            : taskControl.reason
          : `${taskControl.reason} Execution is in progress.`,
        details: details('Execution', [
          ['Tool', `${event.extension_id}/${event.tool_name}`],
          ['Tool call', event.tool_call_id],
          ['Authorization ID', event.authorization_id],
          ['Request hash', event.request_hash],
          ...(!completed
            ? ([
                ['Task scope', event.task_scope_status],
                ['Review status', event.review_status],
                ['Decision reason', event.decision_reason_code],
                ['Task control hash', event.task_control_hash],
                ['Control provenance', event.task_control_provenance],
                ['Task check', preAssessment.label],
                ['Task evidence', preAssessment.reason],
                ['Evidence records', String(event.intent_assessment.evidence_count)],
                ['Intent evaluation', event.intent_evaluation_hash],
                ...event.conformance_evaluation_hashes.map(
                  (hash, index) => [`Conformance evidence ${index + 1}`, hash] as [string, string]
                ),
              ] as [string, string][])
            : []),
          ...(completed?.record_hash
            ? ([['Record hash', completed.record_hash]] as [string, string][])
            : []),
          ...(completed
            ? ([
                ['Task scope', completed.task_scope_status],
                ['Review status', completed.review_status],
                ['Decision reason', completed.decision_reason_code],
                ['Task control hash', completed.task_control_hash],
                ['Control provenance', completed.task_control_provenance],
                ['Execution lineage', completed.execution_lineage_hash],
                ['Task check (before)', preAssessment.label],
                ['Task evidence (before)', preAssessment.reason],
                [
                  'Evidence records (before)',
                  String(completed.intent_pre_assessment.evidence_count),
                ],
                ['Task check (after)', completeAssessment!.label],
                ['Task evidence (after)', completeAssessment!.reason],
                [
                  'Evidence records (after)',
                  String(completed.intent_complete_assessment.evidence_count),
                ],
                ['Intent evaluation (before)', completed.intent_pre_evaluation_hash],
                ...(completed.intent_complete_evaluation_hash
                  ? ([['Intent evaluation (after)', completed.intent_complete_evaluation_hash]] as [
                      string,
                      string,
                    ][])
                  : []),
              ] as [string, string][])
            : []),
        ]),
      };
    }
    case 'ACTION_COMPLETED': {
      if (
        recordedAuthorizationIds.has(event.authorization_id) ||
        startedAuthorizationIds.has(event.authorization_id)
      ) {
        return null;
      }
      const taskControl = projectCompletedTaskControl(event);
      const preAssessment = intentAssessmentCopy(event.intent_pre_assessment);
      const completeAssessment = intentAssessmentCopy(event.intent_complete_assessment);
      return {
        ...base,
        category: 'ACTIVITY',
        taskControl,
        kind: 'ACTION_RECORDED',
        status: event.state === 'EXECUTION_UNKNOWN' ? 'WARNING' : 'VERIFIED',
        title: event.state === 'EXECUTION_UNKNOWN' ? 'Check result' : 'Action completed',
        summary:
          event.state === 'EXECUTION_UNKNOWN'
            ? `${taskControl.reason} The final state could not be confirmed.`
            : taskControl.reason,
        details: details('Execution', [
          ['Tool call', event.tool_call_id],
          ['Authorization ID', event.authorization_id],
          ['Outcome', event.outcome],
          ...(event.record_hash
            ? ([['Record hash', event.record_hash]] as [string, string][])
            : []),
          ['Task scope', event.task_scope_status],
          ['Review status', event.review_status],
          ['Decision reason', event.decision_reason_code],
          ['Task control hash', event.task_control_hash],
          ['Control provenance', event.task_control_provenance],
          ['Execution lineage', event.execution_lineage_hash],
          ['Task check (before)', preAssessment.label],
          ['Task evidence (before)', preAssessment.reason],
          ['Evidence records (before)', String(event.intent_pre_assessment.evidence_count)],
          ['Task check (after)', completeAssessment.label],
          ['Task evidence (after)', completeAssessment.reason],
          ['Evidence records (after)', String(event.intent_complete_assessment.evidence_count)],
          ['Intent evaluation (before)', event.intent_pre_evaluation_hash],
          ...(event.intent_complete_evaluation_hash
            ? ([['Intent evaluation (after)', event.intent_complete_evaluation_hash]] as [
                string,
                string,
              ][])
            : []),
        ]),
      };
    }
    case 'RESTORE_PREPARED':
      if (completedRestoreIds.has(event.restore_id) || recordedRestoreIds.has(event.restore_id)) {
        return null;
      }
      return {
        ...base,
        category: 'DECISION',
        kind: 'FILE_RESTORE_PREPARED',
        status: 'PENDING',
        title: `Restore prepared · ${event.relative_path}`,
        summary: 'The saved copy passed its initial checks.',
        details: details('Restore', [
          ['Restore ID', event.restore_id],
          ['Recovery ID', event.recovery_id],
          ['Content hash', event.content_hash],
        ]),
      };
    case 'RESTORE_COMPLETED':
      if (recordedRestoreIds.has(event.restore_id)) return null;
      return {
        ...base,
        category: 'CHANGE',
        kind: 'FILE_RESTORE_RECORDED',
        status: 'VERIFIED',
        title: `File restored · ${event.relative_path}`,
        summary: 'Saved copy restored and recorded.',
        details: details('Restore', [
          ['Restore ID', event.restore_id],
          ['Recovery ID', event.recovery_id],
          ['Record hash', event.record_hash],
        ]),
      };
  }
}

export function mergeRuntimeAuditPage(
  timeline: TaskAuditTimeline,
  page: AccordLockSessionAuditPage
): TaskAuditTimeline {
  const recordedAuthorizationIds = baseDetailValues(timeline, 'Execution authorization');
  const recordedRestoreIds = baseDetailValues(timeline, 'Restore ID');
  const completedByAuthorization = new Map(
    page.events
      .filter(
        (event): event is Extract<AccordLockSessionAuditEvent, { type: 'ACTION_COMPLETED' }> =>
          event.type === 'ACTION_COMPLETED'
      )
      .map((event) => [event.authorization_id, event])
  );
  const completedRestoreIds = new Set(
    page.events
      .filter((event) => event.type === 'RESTORE_COMPLETED')
      .map((event) => event.restore_id)
  );
  const startedAuthorizationIds = new Set(
    page.events
      .filter((event) => event.type === 'ACTION_STARTED')
      .map((event) => event.authorization_id)
  );
  const ledgerEvents = page.events
    .map((event) =>
      eventFromLedger(
        event,
        completedByAuthorization,
        completedRestoreIds,
        startedAuthorizationIds,
        recordedAuthorizationIds,
        recordedRestoreIds
      )
    )
    .filter((event): event is TaskAuditEvent => event !== null);
  const ledgerHasAccessState = ledgerEvents.some((event) =>
    ['ACCESS_ACTIVE', 'ACCESS_REVOKED'].includes(event.kind)
  );
  const retained = timeline.events.filter(
    (event) =>
      !ledgerHasAccessState ||
      !['ACCESS_ACTIVE', 'ACCESS_INACTIVE', 'ACCESS_REVOKED'].includes(event.kind)
  );
  const events = [...retained, ...ledgerEvents].filter(
    (event, index, values) => values.findIndex((candidate) => candidate.id === event.id) === index
  );
  return {
    events,
    historyScope: 'RUNTIME_LEDGER',
    issueCount: events.filter((event) => ['BLOCKED', 'FAILED', 'WARNING'].includes(event.status))
      .length,
    reversibleCount: timeline.reversibleCount,
    scopeNotice:
      page.next_offset === null
        ? 'Verified against the execution log.'
        : `Loaded the latest ${page.events.length} of ${page.total_events} runtime records.`,
    verifiedActionCount: timeline.verifiedActionCount,
  };
}

export function mergeRuntimeAuditPages(
  timeline: TaskAuditTimeline,
  pages: readonly AccordLockSessionAuditPage[]
): TaskAuditTimeline {
  if (pages.length === 0) return timeline;
  const first = pages[0];
  return mergeRuntimeAuditPage(timeline, {
    ...first,
    next_offset: null,
    events: pages.flatMap((page) => page.events),
  });
}

export function formatRuntimeTaskAuditExport(
  timeline: TaskAuditTimeline,
  pages: readonly AccordLockSessionAuditPage[]
): string {
  if (pages.length === 0) {
    throw new Error('AccordLock runtime audit pages are required');
  }
  const first = pages[0];
  return `${JSON.stringify(
    {
      schemaVersion: 2,
      recordType: 'accordlock.task-audit-bundle',
      historyScope: 'RUNTIME_LEDGER',
      snapshot: {
        taskId: first.task_id,
        sessionId: first.session_id,
        runId: first.run_id,
        snapshotRevision: first.snapshot_revision,
        snapshotAt: first.snapshot_at,
        totalEvents: first.total_events,
      },
      runtimePages: pages,
      projection: {
        events: timeline.events,
      },
    },
    null,
    2
  )}\n`;
}
