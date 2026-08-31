import type { AccordLockSessionAuditPage } from '../accordlockRuntime';

/**
 * Closed renderer/preload surface for AccordLock task control.
 *
 * These channel names are transport identifiers only. Possessing them conveys
 * no authority: Electron main must validate the sender and the runtime must
 * acknowledge every decision over its private ControlChannel.
 */
export const ACCORDLOCK_TASK_AUTHORIZATION_EVENT =
  'accordlock:control:task-authorization:ready' as const;
export const ACCORDLOCK_TASK_AUTHORIZATION_GET_PENDING =
  'accordlock:control:task-authorization:get-pending' as const;
export const ACCORDLOCK_TASK_AUTHORIZATION_PREPARE =
  'accordlock:control:task-authorization:prepare' as const;
export const ACCORDLOCK_TASK_AUTHORIZATION_DECIDE =
  'accordlock:control:task-authorization:decide' as const;
export const ACCORDLOCK_TASK_AUTHORIZATION_REVOKE =
  'accordlock:control:task-authorization:revoke' as const;
export const ACCORDLOCK_TASK_RESTORE = 'accordlock:control:recovery:restore' as const;
export const ACCORDLOCK_TASK_AUDIT = 'accordlock:control:audit:get' as const;

export const ACCORDLOCK_CONTROL_PROTOCOL = 'accordlock.desktop.control/v2' as const;

export type AccordLockTaskAuthorizationDecision = 'APPROVE' | 'REJECT';

export interface AccordLockTaskRequest {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
  objective: string;
}

export interface AccordLockTaskCapability {
  extension_id: string;
  tool_name: string;
  display_name: string;
  description?: string;
  operation_type: 'READ' | 'WRITE' | 'EXECUTE' | 'NETWORK' | 'ADMIN';
}

export interface AccordLockTaskPolicy {
  schema_version: 2;
  task_objective_hash: string;
  preauthorized_capabilities: Array<{
    extension_id: string;
    tool_name: string;
  }>;
  protected_paths: string[];
}

export interface AccordLockTaskAuthorization {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  authorization_id: string;
  task_id: string;
  session_id: string;
  authorization_digest: string;
  objective: string;
  workspace_root: string;
  prepared_at: number;
  expires_at: number;
  task_policy: AccordLockTaskPolicy;
  task_policy_hash: string;
  capabilities: AccordLockTaskCapability[];
}

export interface AccordLockTaskAuthorizationDecisionRequest {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  authorization_id: string;
  task_id: string;
  authorization_digest: string;
  decision: AccordLockTaskAuthorizationDecision;
}

export interface AccordLockTaskAuthorizationDecisionAck {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  authorization_id: string;
  task_id: string;
  authorization_digest: string;
  status: 'APPROVED' | 'REJECTED';
  reason_code: string;
  reason: string;
  decision_record: {
    record_id: string;
    record_digest: string;
    recorded_at: number;
  };
}

export interface AccordLockTaskAuthorizationRevokeRequest {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
}

export interface AccordLockTaskAuthorizationRevokeAck {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
  task_id: string | null;
  run_id: string | null;
  status: 'REVOKED';
  reason_code:
    | 'NO_SESSION_AUTHORIZATION'
    | 'NO_AUTHORIZATION_INSTALLED'
    | 'TASK_AUTHORIZATION_REVOKED'
    | 'TASK_AUTHORIZATION_ALREADY_REVOKED';
  revocation_record: {
    request_id: string | null;
    revocation_digest: string | null;
  };
}

export interface AccordLockTaskRestoreRequest {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
  recovery_id: string;
}

export interface AccordLockTaskAuditRequest {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
  offset: number;
  limit: number;
  snapshot_revision: number | null;
}

export interface AccordLockTaskAuditAck {
  protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
  schema_version: 2;
  session_id: string;
  page: AccordLockSessionAuditPage;
}

export interface AccordLockTaskRestoreRecord {
  restore_id: string;
  record_hash: string;
  relative_path: string;
  content_sha256: string;
  completed_at: number;
}

export type AccordLockTaskRestoreAck =
  | {
      protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
      schema_version: 2;
      session_id: string;
      recovery_id: string;
      status: 'RESTORED' | 'ALREADY_RESTORED';
      record: AccordLockTaskRestoreRecord;
    }
  | {
      protocol: typeof ACCORDLOCK_CONTROL_PROTOCOL;
      schema_version: 2;
      session_id: string;
      recovery_id: string;
      status: 'CANCELLED';
      record: null;
    };
