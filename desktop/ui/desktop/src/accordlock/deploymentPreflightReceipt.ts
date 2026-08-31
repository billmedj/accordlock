import { z } from 'zod';
import type {
  DeploymentPreflightCheckKind,
  DeploymentPreflightResultView,
} from '../components/accordlock/DeploymentPreflightResult';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.string().uuid();
const unixSeconds = z.number().int().nonnegative().safe();
const positiveInteger = z.number().int().positive().safe();
const canonicalCommit = z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u);
const reasonCode = z.string().regex(/^[A-Z][A-Z0-9_]{1,127}$/u);
function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
  });
}
const boundedText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine((value) => !hasControlCharacter(value));

const candidateSchema = z
  .object({
    repository: boundedText(201),
    pull_number: positiveInteger,
    commit_sha: canonicalCommit,
    workflow_ref: boundedText(256),
    actions_run_id: positiveInteger,
    ecr_repository: boundedText(512),
    image_digest: digest,
  })
  .strict();

const targetSchema = z
  .object({
    cluster_identity: boundedText(512),
    cluster_endpoint: boundedText(2_048),
    cluster_ca_hash: digest,
    namespace: boundedText(253),
    deployment: boundedText(253),
    deployment_uid: boundedText(512),
    resource_version: boundedText(256),
    container: boundedText(253),
    observed_image_digest: digest,
  })
  .strict();

const checkSchema = z
  .object({
    kind: z.enum(['CODE_REVIEW', 'BUILD', 'IMAGE', 'TARGET']),
    status: z.enum(['PASSED', 'BLOCKED', 'INDETERMINATE']),
    summary: boundedText(512),
    reason_code: reasonCode.nullish(),
    observed_at: unixSeconds.nullish(),
    freshness_seconds: z.number().int().nonnegative().max(86_400).nullish(),
    evidence_reference: boundedText(2_048).nullish(),
  })
  .strict();

const unsignedReceiptSchema = z
  .object({
    schema_version: z.literal(2),
    check_id: uuid,
    request_id: uuid,
    environment_id: boundedText(256),
    environment_profile_hash: digest,
    runner_id: uuid,
    runner_registration_hash: digest,
    dispatch_hash: digest,
    policy_decision_hash: digest.nullish(),
    outcome: z.enum(['PASSED', 'BLOCKED', 'INDETERMINATE']),
    reason_codes: z.array(reasonCode).max(64),
    candidate: candidateSchema,
    target: targetSchema,
    checks: z.array(checkSchema).length(4),
    evidence_root: digest.nullish(),
    started_at: unixSeconds,
    completed_at: unixSeconds,
    valid_until: unixSeconds.nullish(),
    effect: z.literal('NONE'),
    deployment_performed: z.literal(false),
    evaluation_attestation: z.record(z.unknown()).nullish(),
  })
  .strict();

export const signedDeploymentPreflightReceiptSchema = z
  .object({
    payload: unsignedReceiptSchema,
    receipt_hash: digest,
    signer_key_id: boundedText(256),
    receipt_public_key_hash: digest,
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/u),
  })
  .strict()
  .superRefine((receipt, context) => {
    const payload = receipt.payload;
    const expectedKinds = ['CODE_REVIEW', 'BUILD', 'IMAGE', 'TARGET'] as const;
    payload.checks.forEach((check, index) => {
      if (check.kind !== expectedKinds[index]) {
        context.addIssue({
          code: 'custom',
          path: ['payload', 'checks', index, 'kind'],
          message: 'checks must be complete and ordered',
        });
      }
    });
    if (payload.completed_at < payload.started_at) {
      context.addIssue({
        code: 'custom',
        path: ['payload', 'completed_at'],
        message: 'must not precede started_at',
      });
    }

    const determinate = payload.outcome !== 'INDETERMINATE';
    if (
      determinate &&
      (!payload.policy_decision_hash ||
        !payload.evidence_root ||
        !payload.evaluation_attestation ||
        !payload.valid_until ||
        payload.valid_until <= payload.completed_at)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['payload', 'outcome'],
        message: 'determinate receipts require complete verified evidence',
      });
    }
    if (payload.outcome === 'PASSED' && payload.checks.some((check) => check.status !== 'PASSED')) {
      context.addIssue({
        code: 'custom',
        path: ['payload', 'checks'],
        message: 'a passed receipt requires four passed checks',
      });
    }
    if (
      payload.outcome === 'BLOCKED' &&
      !payload.checks.some((check) => check.status === 'BLOCKED')
    ) {
      context.addIssue({
        code: 'custom',
        path: ['payload', 'checks'],
        message: 'a blocked receipt requires a blocked check',
      });
    }
    if (
      payload.outcome === 'INDETERMINATE' &&
      !payload.checks.some((check) => check.status === 'INDETERMINATE')
    ) {
      context.addIssue({
        code: 'custom',
        path: ['payload', 'checks'],
        message: 'an indeterminate receipt requires an indeterminate check',
      });
    }
  });

export type SignedDeploymentPreflightReceipt = z.infer<
  typeof signedDeploymentPreflightReceiptSchema
>;

const PASSED_SUMMARY: Readonly<Record<DeploymentPreflightCheckKind, string>> = {
  CODE_REVIEW: 'Approved commit matches',
  BUILD: 'Successful run matches the commit',
  IMAGE: 'Signed digest matches the build',
  TARGET: 'Deployment state is unchanged',
};

const REASON_SUMMARY: Readonly<Record<string, string>> = {
  REVIEW_NOT_APPROVED: 'Required review is missing',
  REVIEW_COMMIT_MISMATCH: 'Review applies to another commit',
  BUILD_NOT_SUCCESSFUL: 'The build did not succeed',
  BUILD_FAILED: 'The build did not succeed',
  BUILD_COMMIT_MISMATCH: 'The build used another commit',
  ARTIFACT_SIGNATURE_INVALID: 'The image signature is invalid',
  ARTIFACT_QUARANTINED: 'The image is quarantined',
  IMAGE_TRUST_FAILED: 'Image trust verification failed',
  TRANSFORM_OUTPUT_MISMATCH: 'The image does not match the build output',
  TARGET_IDENTITY_MISMATCH: 'The deployment target changed',
  TARGET_STATE_MISMATCH: 'The deployment state changed',
  EVIDENCE_STALE: 'The evidence is no longer current',
  PROVIDER_AUTHENTICATION_FAILED: 'Connection authentication failed',
  PROVIDER_UNAVAILABLE: 'The provider is unavailable',
  PROVIDER_RESPONSE_INVALID: 'The provider returned an invalid response',
  TRUST_SIGNAL_UNAVAILABLE: 'Image trust evidence is unavailable',
  CONNECTION_NOT_READY: 'The environment needs attention',
};

export function parseSignedDeploymentPreflightReceipt(
  value: unknown
): SignedDeploymentPreflightReceipt {
  return signedDeploymentPreflightReceiptSchema.parse(value);
}

export function projectDeploymentPreflightResult(
  receipt: SignedDeploymentPreflightReceipt
): DeploymentPreflightResultView {
  const payload = receipt.payload;
  return {
    checkId: payload.check_id,
    outcome: payload.outcome,
    completedAt: payload.completed_at,
    validUntil: payload.valid_until ?? null,
    environmentProfileHash: payload.environment_profile_hash,
    receiptHash: receipt.receipt_hash,
    receiptJson: JSON.stringify(receipt),
    reasonCodes: payload.reason_codes,
    checks: payload.checks.map((check) => {
      const reason = check.reason_code ?? undefined;
      return {
        kind: check.kind,
        status: check.status,
        summary:
          check.status === 'PASSED'
            ? PASSED_SUMMARY[check.kind]
            : reason
              ? (REASON_SUMMARY[reason] ??
                (check.status === 'BLOCKED'
                  ? 'A verified check failed'
                  : 'Could not verify this check'))
              : check.status === 'BLOCKED'
                ? 'A verified check failed'
                : 'Could not verify this check',
        ...(reason ? { reasonCode: reason } : {}),
      };
    }),
  };
}
