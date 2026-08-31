export type TaskControlStatus =
  | 'WITHIN_APPROVED_ACCESS'
  | 'REVIEWED'
  | 'OUTSIDE_TASK'
  | 'NOT_APPROVED'
  | 'BLOCKED';

export type TaskControlProjection = Readonly<{
  label:
    | 'Within approved access'
    | 'Reviewed'
    | 'Outside approved access'
    | 'Not approved'
    | 'Blocked';
  reason: string;
  provenance: 'DECISION_BOUND' | 'LINEAGE_BOUND' | 'EMBEDDED' | 'RECONSTRUCTED';
  status: TaskControlStatus;
}>;

type CompletedTaskControl = Readonly<{
  decision_reason_code: 'POLICY_CONFORMANT' | 'ACTION_APPROVAL_ACCEPTED';
  review_status: 'NOT_REQUIRED' | 'APPROVED';
  task_control_provenance: 'DECISION_BOUND' | 'LINEAGE_BOUND' | 'EMBEDDED' | 'RECONSTRUCTED';
  task_scope_status: 'WITHIN_APPROVED_ACCESS' | 'REVIEW_REQUIRED';
}>;

function projection(
  status: TaskControlStatus,
  label: TaskControlProjection['label'],
  reason: string,
  provenance: TaskControlProjection['provenance'] = 'LINEAGE_BOUND'
): TaskControlProjection {
  const provenanceNote =
    provenance === 'RECONSTRUCTED'
      ? ' This legacy status was reconstructed from its verified authorization decision.'
      : '';
  return Object.freeze({ label, provenance, reason: `${reason}${provenanceNote}`, status });
}

export function projectCompletedTaskControl(event: CompletedTaskControl): TaskControlProjection {
  if (
    event.task_scope_status === 'WITHIN_APPROVED_ACCESS' &&
    event.review_status === 'NOT_REQUIRED' &&
    event.decision_reason_code === 'POLICY_CONFORMANT'
  ) {
    return projection(
      'WITHIN_APPROVED_ACCESS',
      'Within approved access',
      'The action stayed within the approved access.',
      event.task_control_provenance
    );
  }
  if (
    event.task_scope_status === 'REVIEW_REQUIRED' &&
    event.review_status === 'APPROVED' &&
    event.decision_reason_code === 'ACTION_APPROVAL_ACCEPTED'
  ) {
    return projection(
      'REVIEWED',
      'Reviewed',
      'This exact action was approved before it ran.',
      event.task_control_provenance
    );
  }
  throw new Error('Completed action task control is invalid');
}

export function projectDeniedTaskControl(reasonCode: string): TaskControlProjection {
  if (
    reasonCode === 'CONFORMANCE_SCOPE_MISMATCH' ||
    reasonCode === 'CONFORMANCE_EVALUATION_INVALID'
  ) {
    return projection(
      'OUTSIDE_TASK',
      'Outside approved access',
      'AccordLock could not verify this action within the approved access.'
    );
  }
  if (reasonCode === 'ACTION_APPROVAL_DENIED') {
    return projection('NOT_APPROVED', 'Not approved', 'The requested action was not approved.');
  }
  return projection('BLOCKED', 'Blocked', 'The runtime blocked this action.');
}
