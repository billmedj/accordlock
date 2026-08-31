import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import path from 'node:path';
import type {
  AccordLockApprovalChannelDispatchBundle,
  AccordLockApprovalChannelInput,
} from './accordlockApprovalChannels';
import { resolveAccordLockRuntimeBundle } from './accordlockRuntime';

export const ACCORDLOCK_NOTIFICATION_FRAME_MAGIC = 'ALN1';
export const ACCORDLOCK_CONNECTION_TEST_FRAME_MAGIC = 'ALT1';
export const ACCORDLOCK_NOTIFICATION_MAX_REQUEST_BYTES = 32 * 1_024;
const MAX_RESPONSE_BYTES = 4 * 1_024;
const DEFAULT_TIMEOUT_MS = 50_000;
const APPROVAL_ID = /^action:sha256:[0-9a-f]{64}$/u;
const OUTBOX_KEY = /^(?!0{64}$)[0-9a-f]{64}$/u;
const NOTIFICATION_OS_ENV_ALLOWLIST = [
  'SystemRoot',
  'WINDIR',
  'TEMP',
  'TMP',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
] as const;

type NotificationSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions
) => ChildProcess;

type NotificationAbortSignal = {
  readonly aborted: boolean;
  addEventListener(type: 'abort', listener: () => void, options: { once: true }): void;
  removeEventListener(type: 'abort', listener: () => void): void;
};

export type AccordLockNotificationDispatchReport = {
  configured: number;
  dead_lettered: number;
  delivered: number;
  enqueued: number;
  existing: number;
  idle: number;
  next_retry_at: number | null;
  retry_scheduled: number;
  schema_version: 1;
};

type DispatchOptions = {
  acceptDirtyDevelopmentMarker?: boolean;
  approvalId: string;
  signal?: NotificationAbortSignal;
  baseEnvironment?: Readonly<Record<string, string | undefined>>;
  binDirectory: string;
  bundle: AccordLockApprovalChannelDispatchBundle;
  dataDirectory: string;
  expectedBinarySha256?: string;
  expiresAt: number;
  receivedAt: number;
  platform?: NodeJS.Platform;
  spawnProcess?: NotificationSpawn;
  timeoutMs?: number;
};

type NotificationChannelRequest =
  | { access_token: string; channel: 'SLACK'; destination: string }
  | {
      access_token: string;
      channel: 'MICROSOFT_TEAMS';
      conversation_id: string;
      service_url: string;
    }
  | { bot_token: string; channel: 'TELEGRAM'; chat_id: string }
  | {
      access_token: string;
      channel: 'WHATSAPP';
      phone_number_id: string;
      recipient: string;
    };

type NotificationRequest = {
  schema_version: 1;
  approval_id: string;
  received_at: number;
  expires_at: number;
  outbox_key_hex: string;
  channels: NotificationChannelRequest[];
};

export type AccordLockConnectionTestReport = {
  accepted: boolean;
  channel: AccordLockApprovalChannelInput['channel'];
  outcome: 'DELIVERED' | 'RETRYABLE_FAILURE' | 'REJECTED' | 'UNKNOWN';
  schema_version: 1;
};

type ConnectionTestOptions = Omit<
  DispatchOptions,
  'approvalId' | 'dataDirectory' | 'expiresAt' | 'receivedAt'
>;

function requestChannel(input: AccordLockApprovalChannelInput): NotificationChannelRequest {
  if (!input.enabled) throw new Error('Disabled approval channel reached notification dispatch');
  switch (input.channel) {
    case 'SLACK':
      return {
        channel: 'SLACK',
        destination: input.destination,
        access_token: input.accessToken,
      };
    case 'MICROSOFT_TEAMS':
      return {
        channel: 'MICROSOFT_TEAMS',
        conversation_id: input.conversationId,
        service_url: input.serviceUrl,
        access_token: input.accessToken,
      };
    case 'TELEGRAM':
      return { channel: 'TELEGRAM', chat_id: input.chatId, bot_token: input.botToken };
    case 'WHATSAPP':
      return {
        channel: 'WHATSAPP',
        recipient: input.recipient,
        phone_number_id: input.phoneNumberId,
        access_token: input.accessToken,
      };
  }
}

export function encodeAccordLockNotificationRequest(
  approvalId: string,
  receivedAt: number,
  expiresAt: number,
  bundle: AccordLockApprovalChannelDispatchBundle
): Buffer {
  if (
    !APPROVAL_ID.test(approvalId) ||
    !Number.isSafeInteger(receivedAt) ||
    receivedAt < 0 ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= receivedAt ||
    expiresAt - receivedAt > 5 * 60 ||
    !OUTBOX_KEY.test(bundle.outboxKeyHex) ||
    bundle.channels.length === 0 ||
    bundle.channels.length > 4 ||
    new Set(bundle.channels.map((channel) => channel.channel)).size !== bundle.channels.length
  ) {
    throw new Error('Approval notification request is invalid');
  }
  const request: NotificationRequest = {
    schema_version: 1,
    approval_id: approvalId,
    received_at: receivedAt,
    expires_at: expiresAt,
    outbox_key_hex: bundle.outboxKeyHex,
    channels: bundle.channels.map(requestChannel),
  };
  const body = Buffer.from(JSON.stringify(request), 'utf8');
  if (body.length === 0 || body.length > ACCORDLOCK_NOTIFICATION_MAX_REQUEST_BYTES) {
    body.fill(0);
    throw new Error('Approval notification request exceeds its size limit');
  }
  const frame = Buffer.allocUnsafe(8 + body.length);
  frame.write(ACCORDLOCK_NOTIFICATION_FRAME_MAGIC, 0, 4, 'ascii');
  frame.writeUInt32BE(body.length, 4);
  body.copy(frame, 8);
  body.fill(0);
  return frame;
}

export function encodeAccordLockConnectionTestRequest(
  bundle: AccordLockApprovalChannelDispatchBundle
): Buffer {
  if (bundle.channels.length !== 1 || !bundle.channels[0]?.enabled) {
    throw new Error('Approval channel connection test is invalid');
  }
  const body = Buffer.from(
    JSON.stringify({
      schema_version: 1,
      channel: requestChannel(bundle.channels[0]),
    }),
    'utf8'
  );
  if (body.length === 0 || body.length > ACCORDLOCK_NOTIFICATION_MAX_REQUEST_BYTES) {
    body.fill(0);
    throw new Error('Approval channel connection test exceeds its size limit');
  }
  const frame = Buffer.allocUnsafe(8 + body.length);
  frame.write(ACCORDLOCK_CONNECTION_TEST_FRAME_MAGIC, 0, 4, 'ascii');
  frame.writeUInt32BE(body.length, 4);
  body.copy(frame, 8);
  body.fill(0);
  return frame;
}

export function parseAccordLockConnectionTestReport(value: string): AccordLockConnectionTestReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Approval channel connection test response is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    !exactKeys(parsed as Record<string, unknown>, [
      'accepted',
      'channel',
      'outcome',
      'schema_version',
    ])
  ) {
    throw new Error('Approval channel connection test response is invalid');
  }
  const report = parsed as Record<string, unknown>;
  if (
    report.schema_version !== 1 ||
    typeof report.accepted !== 'boolean' ||
    !['SLACK', 'MICROSOFT_TEAMS', 'TELEGRAM', 'WHATSAPP'].includes(String(report.channel)) ||
    !['DELIVERED', 'RETRYABLE_FAILURE', 'REJECTED', 'UNKNOWN'].includes(String(report.outcome)) ||
    report.accepted !== (report.outcome === 'DELIVERED')
  ) {
    throw new Error('Approval channel connection test response is invalid');
  }
  return report as AccordLockConnectionTestReport;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function boundedCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 4;
}

export function parseAccordLockNotificationReport(
  value: string
): AccordLockNotificationDispatchReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Approval notification response is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    !exactKeys(parsed as Record<string, unknown>, [
      'configured',
      'dead_lettered',
      'delivered',
      'enqueued',
      'existing',
      'idle',
      'next_retry_at',
      'retry_scheduled',
      'schema_version',
    ])
  ) {
    throw new Error('Approval notification response is invalid');
  }
  const report = parsed as Record<string, unknown>;
  const counts = [
    report.configured,
    report.dead_lettered,
    report.delivered,
    report.enqueued,
    report.existing,
    report.idle,
    report.retry_scheduled,
  ];
  const nextRetryAt = report.next_retry_at;
  if (
    report.schema_version !== 1 ||
    !counts.every(boundedCount) ||
    !(
      nextRetryAt === null ||
      (typeof nextRetryAt === 'number' && Number.isSafeInteger(nextRetryAt) && nextRetryAt >= 0)
    ) ||
    (nextRetryAt !== null && (report.retry_scheduled as number) + (report.idle as number) === 0) ||
    (report.enqueued as number) + (report.existing as number) !== report.configured ||
    (report.dead_lettered as number) +
      (report.delivered as number) +
      (report.idle as number) +
      (report.retry_scheduled as number) !==
      report.configured
  ) {
    throw new Error('Approval notification response is invalid');
  }
  return report as AccordLockNotificationDispatchReport;
}

export async function dispatchAccordLockReviewNotification({
  acceptDirtyDevelopmentMarker = false,
  approvalId,
  signal,
  baseEnvironment = process.env,
  binDirectory,
  bundle,
  dataDirectory,
  expectedBinarySha256,
  expiresAt,
  receivedAt,
  platform = process.platform,
  spawnProcess = spawn,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}: DispatchOptions): Promise<AccordLockNotificationDispatchReport> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DEFAULT_TIMEOUT_MS) {
    throw new Error('Approval notification timeout is invalid');
  }
  if (signal?.aborted) {
    throw new Error('Approval notification was cancelled');
  }
  const runtimeBundle = resolveAccordLockRuntimeBundle(
    binDirectory,
    platform,
    acceptDirtyDevelopmentMarker,
    expectedBinarySha256
  );
  const environment: Record<string, string | undefined> = {};
  for (const key of NOTIFICATION_OS_ENV_ALLOWLIST) {
    if (baseEnvironment[key] !== undefined) environment[key] = baseEnvironment[key];
  }
  environment.ACCORDLOCK_NOTIFICATION_DATA_DIR = path.resolve(dataDirectory);
  const frame = encodeAccordLockNotificationRequest(approvalId, receivedAt, expiresAt, bundle);
  if (signal?.aborted) {
    frame.fill(0);
    throw new Error('Approval notification was cancelled');
  }
  let child: ChildProcess;
  try {
    child = spawnProcess(runtimeBundle.binaryPath, ['notify', '--request-stdio'], {
      cwd: path.dirname(runtimeBundle.binaryPath),
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    frame.fill(0);
    throw new Error('Approval notification process could not start');
  }
  if (!child.stdin || !child.stdout) {
    frame.fill(0);
    try {
      child.kill('SIGKILL');
    } catch {
      // A failed spawn may not own a process.
    }
    throw new Error('Approval notification process has no private pipes');
  }
  child.stderr?.resume();

  return new Promise((resolve, reject) => {
    let settled = false;
    let output = Buffer.alloc(0);
    let timer: ReturnType<typeof setTimeout> | null = null;
    function finish(error?: Error, report?: AccordLockNotificationDispatchReport) {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      frame.fill(0);
      output.fill(0);
      if (error) reject(error);
      else if (report) resolve(report);
      else reject(new Error('Approval notification process returned no result'));
    }
    function onAbort() {
      try {
        child.kill('SIGKILL');
      } catch {
        // The process may already have exited.
      }
      finish(new Error('Approval notification was cancelled'));
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // The process may already have exited.
      }
      finish(new Error('Approval notification process timed out'));
    }, timeoutMs);

    child.stdout?.on('data', (chunk: Buffer | string) => {
      if (settled) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (output.length + bytes.length > MAX_RESPONSE_BYTES) {
        try {
          child.kill('SIGKILL');
        } catch {
          // The process may already have exited.
        }
        finish(new Error('Approval notification response is too large'));
        return;
      }
      output = Buffer.concat([output, bytes]);
    });
    child.once('error', () => finish(new Error('Approval notification process could not start')));
    child.once('exit', (code, signal) => {
      if (code !== 0 || signal !== null) {
        finish(new Error('Approval notification process failed'));
        return;
      }
      try {
        finish(undefined, parseAccordLockNotificationReport(output.toString('utf8').trim()));
      } catch {
        finish(new Error('Approval notification response is invalid'));
      }
    });
    child.stdin?.once('error', () => finish(new Error('Approval notification request failed')));
    child.stdin?.end(frame, () => frame.fill(0));
  });
}

export async function dispatchAccordLockConnectionTest({
  acceptDirtyDevelopmentMarker = false,
  signal,
  baseEnvironment = process.env,
  binDirectory,
  bundle,
  expectedBinarySha256,
  platform = process.platform,
  spawnProcess = spawn,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}: ConnectionTestOptions): Promise<AccordLockConnectionTestReport> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > DEFAULT_TIMEOUT_MS) {
    throw new Error('Approval channel connection test timeout is invalid');
  }
  if (signal?.aborted) throw new Error('Approval channel connection test was cancelled');
  const runtimeBundle = resolveAccordLockRuntimeBundle(
    binDirectory,
    platform,
    acceptDirtyDevelopmentMarker,
    expectedBinarySha256
  );
  const environment: Record<string, string | undefined> = {};
  for (const key of NOTIFICATION_OS_ENV_ALLOWLIST) {
    if (baseEnvironment[key] !== undefined) environment[key] = baseEnvironment[key];
  }
  const frame = encodeAccordLockConnectionTestRequest(bundle);
  let child: ChildProcess;
  try {
    child = spawnProcess(runtimeBundle.binaryPath, ['test-notification', '--request-stdio'], {
      cwd: path.dirname(runtimeBundle.binaryPath),
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    frame.fill(0);
    throw new Error('Approval channel connection test could not start');
  }
  if (!child.stdin || !child.stdout) {
    frame.fill(0);
    try {
      child.kill('SIGKILL');
    } catch {
      // A failed spawn may not own a process.
    }
    throw new Error('Approval channel connection test has no private pipes');
  }
  child.stderr?.resume();

  return new Promise((resolve, reject) => {
    let settled = false;
    let output = Buffer.alloc(0);
    let timer: ReturnType<typeof setTimeout> | null = null;
    function finish(error?: Error, report?: AccordLockConnectionTestReport) {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      frame.fill(0);
      output.fill(0);
      if (error) reject(error);
      else if (report) resolve(report);
      else reject(new Error('Approval channel connection test returned no result'));
    }
    function onAbort() {
      try {
        child.kill('SIGKILL');
      } catch {
        // The process may already have exited.
      }
      finish(new Error('Approval channel connection test was cancelled'));
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // The process may already have exited.
      }
      finish(new Error('Approval channel connection test timed out'));
    }, timeoutMs);
    child.stdout?.on('data', (chunk: Buffer | string) => {
      if (settled) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (output.length + bytes.length > MAX_RESPONSE_BYTES) {
        try {
          child.kill('SIGKILL');
        } catch {
          // The process may already have exited.
        }
        finish(new Error('Approval channel connection test response is too large'));
        return;
      }
      output = Buffer.concat([output, bytes]);
    });
    child.once('error', () =>
      finish(new Error('Approval channel connection test could not start'))
    );
    child.once('exit', (code, exitSignal) => {
      if (code !== 0 || exitSignal !== null) {
        finish(new Error('Approval channel connection test failed'));
        return;
      }
      try {
        finish(undefined, parseAccordLockConnectionTestReport(output.toString('utf8').trim()));
      } catch {
        finish(new Error('Approval channel connection test response is invalid'));
      }
    });
    child.stdin?.once('error', () =>
      finish(new Error('Approval channel connection test request failed'))
    );
    child.stdin?.end(frame, () => frame.fill(0));
  });
}
