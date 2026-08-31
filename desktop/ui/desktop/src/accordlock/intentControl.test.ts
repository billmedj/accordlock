import { describe, expect, it } from 'vitest';
import { projectCompletedTaskControl, projectDeniedTaskControl } from './intentControl';

describe('task control projection', () => {
  it('projects only the two valid completed-action controls', () => {
    expect(
      projectCompletedTaskControl({
        task_scope_status: 'WITHIN_APPROVED_ACCESS',
        review_status: 'NOT_REQUIRED',
        decision_reason_code: 'POLICY_CONFORMANT',
        task_control_provenance: 'LINEAGE_BOUND',
      })
    ).toMatchObject({
      label: 'Within approved access',
      status: 'WITHIN_APPROVED_ACCESS',
    });
    expect(
      projectCompletedTaskControl({
        task_scope_status: 'REVIEW_REQUIRED',
        review_status: 'APPROVED',
        decision_reason_code: 'ACTION_APPROVAL_ACCEPTED',
        task_control_provenance: 'LINEAGE_BOUND',
      })
    ).toMatchObject({ label: 'Reviewed', status: 'REVIEWED' });
  });

  it('keeps scope, approval, and runtime denials distinct', () => {
    expect(projectDeniedTaskControl('CONFORMANCE_SCOPE_MISMATCH')).toMatchObject({
      label: 'Outside approved access',
      reason: 'AccordLock could not verify this action within the approved access.',
    });
    expect(projectDeniedTaskControl('CONFORMANCE_EVALUATION_INVALID').label).toBe(
      'Outside approved access'
    );
    expect(projectDeniedTaskControl('ACTION_APPROVAL_DENIED').label).toBe('Not approved');
    expect(projectDeniedTaskControl('CAPABILITY_NOT_APPROVED').label).toBe('Blocked');
  });

  it('marks a reconstructed legacy status without changing its decision', () => {
    expect(
      projectCompletedTaskControl({
        task_scope_status: 'WITHIN_APPROVED_ACCESS',
        review_status: 'NOT_REQUIRED',
        decision_reason_code: 'POLICY_CONFORMANT',
        task_control_provenance: 'RECONSTRUCTED',
      })
    ).toMatchObject({
      provenance: 'RECONSTRUCTED',
      status: 'WITHIN_APPROVED_ACCESS',
    });
  });
});
