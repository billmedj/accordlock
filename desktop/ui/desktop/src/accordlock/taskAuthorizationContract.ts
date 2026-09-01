import { z } from 'zod';
import {
  ACCORDLOCK_CONTROL_PROTOCOL,
  type AccordLockTaskAuthorizationDecision,
  type AccordLockTaskAuthorizationDecisionRequest,
} from './taskIpc';

const boundedText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine((value) => value.trim().length > 0, 'must contain visible text');

const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const nonzeroSha256Digest = sha256Digest.refine(
  (value) => value !== `sha256:${'0'.repeat(64)}`,
  'must not be the zero digest'
);
const unixSeconds = z.number().int().nonnegative().safe();

const preauthorizedCapabilitySchema = z
  .object({
    extension_id: z.literal('developer'),
    tool_name: z.enum(['read', 'tree']),
  })
  .strict();

const protectedPathSchema = boundedText(4_096)
  .refine((value) => /^[\x20-\x7e]+$/u.test(value), 'must contain only printable ASCII')
  .refine((value) => value === value.toLowerCase(), 'must be lowercase')
  .refine(
    (value) =>
      !value.startsWith('/') &&
      !value.endsWith('/') &&
      !value.includes('\\') &&
      !value.includes(':') &&
      value
        .split('/')
        .every((component) => component.length > 0 && component !== '.' && component !== '..'),
    'must be a canonical relative path'
  );

const taskPolicySchema = z
  .object({
    schema_version: z.literal(2),
    task_objective_hash: nonzeroSha256Digest,
    preauthorized_capabilities: z.array(preauthorizedCapabilitySchema).max(16),
    protected_paths: z.array(protectedPathSchema).max(256),
  })
  .strict()
  .superRefine((policy, context) => {
    const automaticKeys = policy.preauthorized_capabilities.map(
      ({ extension_id, tool_name }) => `${extension_id}\u0000${tool_name}`
    );
    automaticKeys.forEach((key, index) => {
      if (index > 0 && automaticKeys[index - 1] >= key) {
        context.addIssue({
          code: 'custom',
          path: ['automatic_capabilities', index],
          message: 'must be sorted and unique',
        });
      }
    });
    policy.protected_paths.forEach((protectedPath, index) => {
      if (index > 0 && policy.protected_paths[index - 1] >= protectedPath) {
        context.addIssue({
          code: 'custom',
          path: ['protected_paths', index],
          message: 'must be sorted and unique',
        });
      }
    });
  });

export const accordLockTaskCapabilitySchema = z
  .object({
    extension_id: boundedText(256),
    tool_name: boundedText(256),
    display_name: boundedText(160),
    description: boundedText(500).optional(),
    operation_type: z.enum(['READ', 'WRITE', 'EXECUTE', 'NETWORK', 'ADMIN']),
  })
  .strict();

export const accordLockTaskAuthorizationSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    authorization_id: z.string().uuid(),
    task_id: z.string().uuid(),
    session_id: boundedText(256),
    authorization_digest: sha256Digest,
    objective: boundedText(4_000),
    workspace_root: boundedText(4_096),
    prepared_at: unixSeconds,
    expires_at: unixSeconds,
    task_policy: taskPolicySchema,
    task_policy_hash: nonzeroSha256Digest,
    capabilities: z.array(accordLockTaskCapabilitySchema).min(1).max(256),
  })
  .strict()
  .superRefine((authorization, context) => {
    if (authorization.expires_at <= authorization.prepared_at) {
      context.addIssue({
        code: 'custom',
        path: ['expires_at'],
        message: 'must be later than prepared_at',
      });
    }

    const exactCapabilities = new Set<string>();
    authorization.capabilities.forEach((capability, index) => {
      const key = `${capability.extension_id}\u0000${capability.tool_name}`;
      if (exactCapabilities.has(key)) {
        context.addIssue({
          code: 'custom',
          path: ['capabilities', index],
          message: 'duplicate exact capability',
        });
      }
      exactCapabilities.add(key);
    });
    authorization.task_policy.preauthorized_capabilities.forEach((capability, index) => {
      const key = `${capability.extension_id}\u0000${capability.tool_name}`;
      if (!exactCapabilities.has(key)) {
        context.addIssue({
          code: 'custom',
          path: ['task_policy', 'preauthorized_capabilities', index],
          message: 'must also be an approved capability',
        });
      }
    });
  });

export const accordLockTaskAuthorizationDecisionAckSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    authorization_id: z.string().uuid(),
    task_id: z.string().uuid(),
    reviewed_authorization_digest: sha256Digest,
    authorization_digest: sha256Digest,
    status: z.enum(['APPROVED', 'REJECTED']),
    reason_code: boundedText(128),
    reason: boundedText(1_000),
    decision_record: z
      .object({
        record_id: boundedText(256),
        record_digest: sha256Digest,
        recorded_at: unixSeconds,
      })
      .strict(),
  })
  .strict();

export const accordLockTaskAuthorizationRevokeAckSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_CONTROL_PROTOCOL),
    schema_version: z.literal(2),
    session_id: boundedText(256),
    task_id: z.string().uuid().nullable(),
    run_id: boundedText(256).nullable(),
    status: z.literal('REVOKED'),
    reason_code: z.enum([
      'NO_SESSION_AUTHORIZATION',
      'NO_AUTHORIZATION_INSTALLED',
      'TASK_AUTHORIZATION_REVOKED',
      'TASK_AUTHORIZATION_ALREADY_REVOKED',
    ]),
    revocation_record: z
      .object({
        request_id: boundedText(256).nullable(),
        revocation_digest: sha256Digest.nullable(),
      })
      .strict(),
  })
  .strict()
  .superRefine((acknowledgement, context) => {
    const runtimeRevocation =
      acknowledgement.reason_code === 'TASK_AUTHORIZATION_REVOKED' ||
      acknowledgement.reason_code === 'TASK_AUTHORIZATION_ALREADY_REVOKED';
    const runtimeBindingComplete =
      acknowledgement.task_id !== null &&
      acknowledgement.run_id !== null &&
      acknowledgement.revocation_record.request_id !== null &&
      acknowledgement.revocation_record.revocation_digest !== null;
    const localRevocationHasNoRecord =
      acknowledgement.revocation_record.request_id === null &&
      acknowledgement.revocation_record.revocation_digest === null;
    if (
      (runtimeRevocation && !runtimeBindingComplete) ||
      (!runtimeRevocation && !localRevocationHasNoRecord)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['revocation_record'],
        message: 'must match the revocation reason',
      });
    }
  });

export const accordLockTaskAuthorizationQueueSchema = z
  .array(accordLockTaskAuthorizationSchema)
  .max(256)
  .superRefine((authorizations, context) => {
    const authorizationIds = new Set<string>();
    const sessionIds = new Set<string>();
    authorizations.forEach((authorization, index) => {
      if (authorizationIds.has(authorization.authorization_id)) {
        context.addIssue({
          code: 'custom',
          path: [index, 'authorization_id'],
          message: 'duplicate authorization_id',
        });
      }
      if (sessionIds.has(authorization.session_id)) {
        context.addIssue({
          code: 'custom',
          path: [index, 'session_id'],
          message: 'duplicate pending session_id',
        });
      }
      authorizationIds.add(authorization.authorization_id);
      sessionIds.add(authorization.session_id);
    });
  });

export type AccordLockTaskCapability = z.infer<typeof accordLockTaskCapabilitySchema>;
export type AccordLockTaskAuthorization = z.infer<typeof accordLockTaskAuthorizationSchema>;
export type AccordLockTaskAuthorizationDecisionAck = z.infer<
  typeof accordLockTaskAuthorizationDecisionAckSchema
>;
export type AccordLockTaskAuthorizationRevokeAck = z.infer<
  typeof accordLockTaskAuthorizationRevokeAckSchema
>;

export function parseAccordLockTaskAuthorization(value: unknown): AccordLockTaskAuthorization {
  return accordLockTaskAuthorizationSchema.parse(value);
}

export function parseAccordLockTaskAuthorizationQueue(
  value: unknown
): AccordLockTaskAuthorization[] {
  if (value === null || value === undefined) return [];
  return accordLockTaskAuthorizationQueueSchema.parse(value);
}

export function parseAccordLockTaskAuthorizationDecisionAck(
  value: unknown,
  authorization: AccordLockTaskAuthorization,
  requestedDecision: AccordLockTaskAuthorizationDecision
): AccordLockTaskAuthorizationDecisionAck {
  const acknowledgement = accordLockTaskAuthorizationDecisionAckSchema.parse(value);
  const sameAuthorization =
    acknowledgement.authorization_id === authorization.authorization_id &&
    acknowledgement.task_id === authorization.task_id &&
    acknowledgement.reviewed_authorization_digest === authorization.authorization_digest;

  if (!sameAuthorization) {
    throw new Error('AccordLock acknowledgement does not match the task authorization');
  }
  if (requestedDecision === 'REJECT' && acknowledgement.status !== 'REJECTED') {
    throw new Error('AccordLock acknowledgement contradicts the rejection');
  }
  if (
    acknowledgement.status === 'REJECTED' &&
    acknowledgement.authorization_digest !== authorization.authorization_digest
  ) {
    throw new Error('AccordLock rejection changed the reviewed task authorization');
  }

  return acknowledgement;
}

export function parseAccordLockTaskAuthorizationRevokeAck(
  value: unknown,
  expectedSessionId: string
): AccordLockTaskAuthorizationRevokeAck {
  const acknowledgement = accordLockTaskAuthorizationRevokeAckSchema.parse(value);
  if (acknowledgement.session_id !== expectedSessionId) {
    throw new Error('AccordLock revocation acknowledgement belongs to another session');
  }
  return acknowledgement;
}

export function createAccordLockTaskAuthorizationDecisionRequest(
  authorization: AccordLockTaskAuthorization,
  decision: AccordLockTaskAuthorizationDecision
): AccordLockTaskAuthorizationDecisionRequest {
  return {
    protocol: ACCORDLOCK_CONTROL_PROTOCOL,
    schema_version: 2,
    authorization_id: authorization.authorization_id,
    task_id: authorization.task_id,
    authorization_digest: authorization.authorization_digest,
    decision,
  };
}
