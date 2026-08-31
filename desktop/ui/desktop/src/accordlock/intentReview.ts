export type IntentReviewKind = 'EVIDENCE_MISSING' | 'EVIDENCE_UNCERTAIN' | 'POLICY_REVIEW';

export interface IntentReviewCopy {
  readonly description: string;
  readonly kind: IntentReviewKind;
}

const REVIEW_DESCRIPTIONS: Readonly<Record<IntentReviewKind, string>> = Object.freeze({
  EVIDENCE_MISSING: "AccordLock couldn't verify this action from the task alone.",
  EVIDENCE_UNCERTAIN: 'This action may go beyond the task you approved.',
  POLICY_REVIEW: 'This action needs your approval.',
});

const MISSING_EVIDENCE = new Set([
  'CONFORMANCE_EVALUATION_MISSING',
  'RESOURCE_QUOTA_MISSING',
  'RESOURCE_RESERVATION_MISSING',
]);

const UNCERTAIN_EVIDENCE = new Set(['CONFORMANCE_INCONCLUSIVE', 'CONFORMANCE_THRESHOLD_UNCERTAIN']);

function policyReasons(value: Readonly<Record<string, unknown>>): readonly string[] {
  if (!Array.isArray(value.reasons)) return [];
  return value.reasons.filter((reason): reason is string => typeof reason === 'string');
}

export function intentReviewCopy(
  policyDecision: Readonly<Record<string, unknown>>
): IntentReviewCopy {
  const reasons = policyReasons(policyDecision);
  if (reasons.some((reason) => MISSING_EVIDENCE.has(reason))) {
    return {
      kind: 'EVIDENCE_MISSING',
      description: REVIEW_DESCRIPTIONS.EVIDENCE_MISSING,
    };
  }
  if (reasons.some((reason) => UNCERTAIN_EVIDENCE.has(reason))) {
    return {
      kind: 'EVIDENCE_UNCERTAIN',
      description: REVIEW_DESCRIPTIONS.EVIDENCE_UNCERTAIN,
    };
  }
  return {
    kind: 'POLICY_REVIEW',
    description: REVIEW_DESCRIPTIONS.POLICY_REVIEW,
  };
}

export function intentReviewDescription(kind: IntentReviewKind): string {
  return REVIEW_DESCRIPTIONS[kind];
}
