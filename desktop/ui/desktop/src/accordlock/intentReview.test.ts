import { describe, expect, it } from 'vitest';
import { intentReviewCopy } from './intentReview';

describe('intentReviewCopy', () => {
  it('explains missing trusted evidence without claiming task alignment', () => {
    expect(
      intentReviewCopy({
        decision: 'REQUIRE_APPROVAL',
        reasons: ['CONFORMANCE_EVALUATION_MISSING'],
      })
    ).toEqual({
      kind: 'EVIDENCE_MISSING',
      description: "AccordLock couldn't verify this action from the task alone.",
    });
  });

  it('distinguishes an uncertain check from missing evidence', () => {
    expect(
      intentReviewCopy({
        decision: 'REQUIRE_APPROVAL',
        reasons: ['CONFORMANCE_THRESHOLD_UNCERTAIN'],
      }).kind
    ).toBe('EVIDENCE_UNCERTAIN');
  });

  it('uses concise policy copy for unknown or absent reason codes', () => {
    expect(intentReviewCopy({ decision: 'REQUIRE_APPROVAL' })).toEqual({
      kind: 'POLICY_REVIEW',
      description: 'This action needs your approval.',
    });
  });
});
