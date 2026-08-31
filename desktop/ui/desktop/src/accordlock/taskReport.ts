import type {
  Message,
  ToolRequestMessageContent,
  ToolResponseMessageContent,
} from '../types/message';
import type { AccordLockTaskRestoreAck } from './taskIpc';

export type TaskExecutionOutcome = 'SUCCEEDED' | 'FAILED';

export type TaskExecutionEvidence = {
  authorizationId: string;
  operation: string;
  outcome: TaskExecutionOutcome;
  recordedAt: number | null;
  reasonCode: string;
  recordHash: string;
  recordId: string;
  recovery: TaskRecoveryEvidence | null;
  requestHash: string;
  resultHash: string | null;
  target: string;
};

export type TaskRecoveryEvidence = {
  contentHash: string;
  recoveryId: string;
  recoveryPath: string;
};

export type TaskReportIntegrity = 'NO_EXECUTION' | 'VERIFIED' | 'NEEDS_CONFIRMATION';

export type TaskReport = {
  evidence: TaskExecutionEvidence[];
  failedActions: number;
  integrity: TaskReportIntegrity;
  successfulActions: number;
  unverifiedActions: number;
};

function reportOperation(operation: string): string {
  const labels: Readonly<Record<string, string>> = {
    DELETE: 'Deleted file',
    EDIT: 'Edited file',
    READ: 'Read file',
    RUN: 'Ran program',
    TREE: 'Listed files',
    WRITE: 'Wrote file',
  };
  return labels[operation] ?? 'Used tool';
}

/**
 * Creates a portable report from runtime-validated records only.
 * Assistant prose is intentionally excluded from this output.
 */
export function formatTaskReportMarkdown(
  objective: string,
  report: TaskReport,
  restoreAcknowledgements: readonly AccordLockTaskRestoreAck[] = []
): string {
  const status =
    report.integrity === 'VERIFIED'
      ? 'Verified'
      : report.integrity === 'NEEDS_CONFIRMATION'
        ? 'Check required'
        : 'No recorded actions';
  const lines = [
    '# AccordLock task report',
    '',
    `Task: ${objective.trim() || 'Untitled task'}`,
    `Status: ${status}`,
    `Verified actions: ${report.evidence.length}`,
  ];

  if (report.unverifiedActions > 0) {
    lines.push(`Unverified actions: ${report.unverifiedActions}`);
  }
  if (restoreAcknowledgements.length > 0) {
    lines.push(`Restore records: ${restoreAcknowledgements.length}`);
  }

  for (const item of report.evidence) {
    lines.push(
      '',
      `- ${reportOperation(item.operation)}: ${item.target} — ${item.outcome === 'SUCCEEDED' ? 'Completed' : 'Failed'}`,
      `  Record ID: ${item.recordId}`,
      `  Verification hash: ${item.recordHash}`
    );
    if (item.resultHash) lines.push(`  Result hash: ${item.resultHash}`);
  }

  for (const acknowledgement of restoreAcknowledgements) {
    if (acknowledgement.status === 'CANCELLED') {
      lines.push('', `- Restore cancelled: ${acknowledgement.recovery_id} — No file was restored`);
      continue;
    }
    lines.push(
      '',
      `- ${acknowledgement.status === 'RESTORED' ? 'Restored file' : 'File already restored'}: ${acknowledgement.record.relative_path} — ${acknowledgement.status === 'RESTORED' ? 'Completed' : 'No new change'}`,
      `  Restore ID: ${acknowledgement.record.restore_id}`,
      `  Record hash: ${acknowledgement.record.record_hash}`,
      `  Content hash: ${acknowledgement.record.content_sha256}`
    );
  }

  return `${lines.join('\n')}\n`;
}

const PROTECTED_DEVELOPER_TOOLS = new Set([
  'delete_file',
  'edit',
  'read',
  'shell',
  'tree',
  'write',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;
const TOOL_EXECUTION_SCHEMA_VERSION = 3;

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function field(value: Record<string, unknown>, camel: string, snake: string): unknown {
  return value[camel] ?? value[snake];
}

function boundedString(value: unknown, maximum = 4_096): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum ? value : null;
}

function protectedToolRequest(request: ToolRequestMessageContent): boolean {
  const metadata = record(request.metadata);
  const toolCall = record(request.toolCall);
  const value = record(toolCall?.value);
  const rawName = boundedString(value?.name, 256) ?? boundedString(metadata?.toolName, 256);
  const extension = boundedString(metadata?.extensionName, 128);
  if (!rawName) return false;

  const separator = rawName.lastIndexOf('__');
  const name = separator >= 0 ? rawName.slice(separator + 2) : rawName;
  const inferredExtension = separator >= 0 ? rawName.slice(0, separator) : extension;
  return inferredExtension === 'developer' && PROTECTED_DEVELOPER_TOOLS.has(name);
}

function structuredContent(response: ToolResponseMessageContent): Record<string, unknown> | null {
  const toolResult = record(response.toolResult);
  if (toolResult?.status === 'success') {
    const value = record(toolResult.value);
    const structured = record(value?.structuredContent);
    if (structured) return structured;
  }
  return record(record(response.metadata)?.rawOutput);
}

function parseEvidence(
  response: ToolResponseMessageContent,
  recordedAt: number | null
): TaskExecutionEvidence | null {
  const structured = structuredContent(response);
  const accordlock = record(structured?.accordlock);
  if (!accordlock) return null;

  const schemaVersion = field(accordlock, 'schemaVersion', 'schema_version');
  const authorizationId = boundedString(
    field(accordlock, 'authorizationId', 'authorization_id'),
    64
  );
  const requestHash = boundedString(field(accordlock, 'requestHash', 'request_hash'), 80);
  const recordId = boundedString(field(accordlock, 'recordId', 'record_id'), 64);
  const recordHash = boundedString(field(accordlock, 'recordHash', 'record_hash'), 80);
  const resultHash = boundedString(field(accordlock, 'resultSha256', 'result_sha256'), 80);
  const status = boundedString(accordlock.status, 64);
  const reasonCode = boundedString(field(accordlock, 'reasonCode', 'reason_code'), 64);

  if (
    schemaVersion !== TOOL_EXECUTION_SCHEMA_VERSION ||
    !authorizationId ||
    !UUID.test(authorizationId) ||
    !requestHash ||
    !DIGEST.test(requestHash) ||
    !recordId ||
    !UUID.test(recordId) ||
    !recordHash ||
    !DIGEST.test(recordHash) ||
    (resultHash !== null && !DIGEST.test(resultHash)) ||
    !status ||
    !reasonCode ||
    !REASON_CODE.test(reasonCode)
  ) {
    return null;
  }

  const result = record(structured?.result);
  const terminalOutcome = boundedString(result?.outcome, 32);
  const recoveryId = boundedString(field(result ?? {}, 'recoveryId', 'recovery_id'), 64);
  const recoveryPath = boundedString(field(result ?? {}, 'recoveryPath', 'recovery_path'));
  const recoveryContentHash = boundedString(
    field(result ?? {}, 'contentSha256', 'content_sha256'),
    80
  );
  const recovery =
    recoveryId &&
    UUID.test(recoveryId) &&
    recoveryPath &&
    recoveryContentHash &&
    DIGEST.test(recoveryContentHash)
      ? {
          contentHash: recoveryContentHash,
          recoveryId,
          recoveryPath,
        }
      : null;
  const rawOperation =
    boundedString(accordlock.operation, 64) ??
    (boundedString(result?.program, 256) ? 'RUN' : 'TOOL');
  const operation = rawOperation === 'DELETE_FILE' ? 'DELETE' : rawOperation;
  const target =
    boundedString(field(accordlock, 'relativePath', 'relative_path')) ??
    boundedString(result?.program, 256) ??
    'Protected action';
  const outcome =
    status === 'TOOL_ERROR' || terminalOutcome === 'FAILED'
      ? ('FAILED' as const)
      : ('SUCCEEDED' as const);

  return {
    authorizationId,
    operation,
    outcome,
    recordedAt,
    reasonCode,
    recordHash,
    recordId,
    recovery,
    requestHash,
    resultHash,
    target,
  };
}

export function buildTaskReport(messages: Message[]): TaskReport {
  const protectedRequestIds = new Set<string>();
  const responses = new Map<
    string,
    { content: ToolResponseMessageContent; recordedAt: number | null }
  >();

  for (const message of messages) {
    for (const content of message.content) {
      if (content.type === 'toolRequest' && protectedToolRequest(content)) {
        protectedRequestIds.add(content.id);
      } else if (content.type === 'toolResponse') {
        responses.set(content.id, {
          content,
          recordedAt:
            Number.isSafeInteger(message.created) && message.created >= 0 ? message.created : null,
        });
      }
    }
  }

  const evidenceByRecord = new Map<string, TaskExecutionEvidence>();
  let unverifiedActions = 0;

  for (const response of responses.values()) {
    const evidence = parseEvidence(response.content, response.recordedAt);
    if (evidence) {
      const previous = evidenceByRecord.get(evidence.recordId);
      if (previous && previous.recordHash !== evidence.recordHash) {
        unverifiedActions += 1;
      } else {
        evidenceByRecord.set(evidence.recordId, evidence);
      }
      continue;
    }

    if (
      protectedRequestIds.has(response.content.id) ||
      record(structuredContent(response.content)?.accordlock)
    ) {
      unverifiedActions += 1;
    }
  }

  const evidence = [...evidenceByRecord.values()];
  const successfulActions = evidence.filter((item) => item.outcome === 'SUCCEEDED').length;
  const failedActions = evidence.length - successfulActions;
  const integrity: TaskReportIntegrity =
    unverifiedActions > 0
      ? 'NEEDS_CONFIRMATION'
      : evidence.length > 0
        ? 'VERIFIED'
        : 'NO_EXECUTION';

  return { evidence, failedActions, integrity, successfulActions, unverifiedActions };
}

export function hasPendingTaskDecision(messages: Message[]): boolean {
  return messages.some((message) =>
    message.content.some(
      (content) =>
        content.type === 'actionRequired' &&
        (content.data.actionType === 'toolConfirmation' ||
          content.data.actionType === 'elicitation')
    )
  );
}
