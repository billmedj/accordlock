import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { describe, expect, it, vi } from 'vitest';
import {
  ACCORDLOCK_CONNECTION_TEST_FRAME_MAGIC,
  ACCORDLOCK_NOTIFICATION_FRAME_MAGIC,
  dispatchAccordLockConnectionTest,
  dispatchAccordLockReviewNotification,
  encodeAccordLockConnectionTestRequest,
  encodeAccordLockNotificationRequest,
  parseAccordLockNotificationReport,
} from './accordlockApprovalNotificationDispatcher';

async function runtimeFixture(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-notifier-'));
  const binary = Buffer.from('fixture verified notifier binary', 'utf8');
  const binaryName = 'accordlock-agent-runtime.exe';
  await fs.writeFile(path.join(directory, binaryName), binary);
  await fs.writeFile(
    path.join(directory, 'accordlock-runtime-build.json'),
    JSON.stringify({
      schema_version: 2,
      distribution: 'AccordLock',
      component: 'accordlock-agent-runtime',
      protocol_version: 2,
      source_commit: '0'.repeat(40),
      source_dirty: true,
      binary: binaryName,
      binary_sha256: createHash('sha256').update(binary).digest('hex'),
    })
  );
  return directory;
}

function fakeChild() {
  const process = new EventEmitter() as EventEmitter & Partial<ChildProcess>;
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const kill = vi.fn(() => true);
  Object.assign(process, { stdin, stdout, stderr, kill });
  return { child: process as unknown as ChildProcess, stdin, stdout, stderr, kill, process };
}

const dispatchBundle = {
  outboxKeyHex: '11'.repeat(32),
  channels: [
    {
      channel: 'SLACK' as const,
      enabled: true,
      destination: 'C12345678',
      accessToken: 'fixture-slack-access-token-00000000',
    },
  ],
};

describe('display-only approval notification dispatch', () => {
  it('sends a fixed-copy connection test through the verified runtime', async () => {
    const frame = encodeAccordLockConnectionTestRequest(dispatchBundle);
    expect(frame.subarray(0, 4).toString('ascii')).toBe(ACCORDLOCK_CONNECTION_TEST_FRAME_MAGIC);
    const request = JSON.parse(frame.subarray(8).toString('utf8')) as Record<string, unknown>;
    expect(request).toEqual({
      schema_version: 1,
      channel: {
        access_token: 'fixture-slack-access-token-00000000',
        channel: 'SLACK',
        destination: 'C12345678',
      },
    });

    const binDirectory = await runtimeFixture();
    const fake = fakeChild();
    const spawnProcess = vi.fn(
      (_command: string, _args: readonly string[], _options: SpawnOptions) => {
        fake.stdin.once('finish', () => {
          fake.stdout.end(
            JSON.stringify({
              accepted: true,
              channel: 'SLACK',
              outcome: 'DELIVERED',
              schema_version: 1,
            })
          );
          fake.process.emit('exit', 0, null);
        });
        return fake.child;
      }
    );
    await expect(
      dispatchAccordLockConnectionTest({
        acceptDirtyDevelopmentMarker: true,
        baseEnvironment: { AWS_SECRET_ACCESS_KEY: 'must-not-be-inherited' },
        binDirectory,
        bundle: dispatchBundle,
        platform: 'win32',
        spawnProcess,
      })
    ).resolves.toMatchObject({ accepted: true, channel: 'SLACK', outcome: 'DELIVERED' });
    expect(spawnProcess.mock.calls[0][1]).toEqual(['test-notification', '--request-stdio']);
    expect(spawnProcess.mock.calls[0][2].env).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
    expect(spawnProcess.mock.calls[0][2].env).not.toHaveProperty(
      'ACCORDLOCK_NOTIFICATION_DATA_DIR'
    );
  });

  it('frames only the exact generic delivery configuration', () => {
    const frame = encodeAccordLockNotificationRequest(
      `action:sha256:${'a'.repeat(64)}`,
      1_799_999_700,
      1_800_000_000,
      {
        outboxKeyHex: '11'.repeat(32),
        channels: [
          {
            channel: 'SLACK',
            enabled: true,
            destination: 'C12345678',
            accessToken: 'fixture-slack-access-token-00000000',
          },
        ],
      }
    );

    expect(frame.subarray(0, 4).toString('ascii')).toBe(ACCORDLOCK_NOTIFICATION_FRAME_MAGIC);
    const length = frame.readUInt32BE(4);
    expect(length).toBe(frame.length - 8);
    const request = JSON.parse(frame.subarray(8).toString('utf8')) as Record<string, unknown>;
    expect(request).toEqual({
      schema_version: 1,
      approval_id: `action:sha256:${'a'.repeat(64)}`,
      received_at: 1_799_999_700,
      expires_at: 1_800_000_000,
      outbox_key_hex: '11'.repeat(32),
      channels: [
        {
          channel: 'SLACK',
          destination: 'C12345678',
          access_token: 'fixture-slack-access-token-00000000',
        },
      ],
    });
    const encoded = frame.toString('utf8');
    expect(encoded).not.toContain('objective');
    expect(encoded).not.toContain('workspace');
    expect(encoded).not.toContain('command');
    expect(encoded).not.toContain('callback');
  });

  it('rejects duplicate providers, disabled channels, and malformed approval bindings', () => {
    const channel = {
      channel: 'SLACK' as const,
      enabled: true,
      destination: 'C12345678',
      accessToken: 'fixture-slack-access-token-00000000',
    };
    expect(() =>
      encodeAccordLockNotificationRequest(`action:sha256:${'a'.repeat(64)}`, 0, 1, {
        outboxKeyHex: '11'.repeat(32),
        channels: [channel, channel],
      })
    ).toThrow('invalid');
    expect(() =>
      encodeAccordLockNotificationRequest(`action:sha256:${'a'.repeat(64)}`, 0, 1, {
        outboxKeyHex: '11'.repeat(32),
        channels: [{ ...channel, enabled: false }],
      })
    ).toThrow('Disabled');
    expect(() =>
      encodeAccordLockNotificationRequest('action:not-a-digest', 0, 1, {
        outboxKeyHex: '11'.repeat(32),
        channels: [channel],
      })
    ).toThrow('invalid');
  });

  it('accepts only an exact, internally consistent secret-free report', () => {
    expect(
      parseAccordLockNotificationReport(
        JSON.stringify({
          schema_version: 1,
          configured: 2,
          enqueued: 1,
          existing: 1,
          delivered: 1,
          retry_scheduled: 0,
          dead_lettered: 0,
          idle: 1,
          next_retry_at: null,
        })
      )
    ).toMatchObject({ configured: 2, delivered: 1, idle: 1 });

    expect(() =>
      parseAccordLockNotificationReport(
        JSON.stringify({
          schema_version: 1,
          configured: 1,
          enqueued: 1,
          existing: 0,
          delivered: 1,
          retry_scheduled: 0,
          dead_lettered: 0,
          idle: 1,
          next_retry_at: null,
        })
      )
    ).toThrow('invalid');

    expect(() =>
      parseAccordLockNotificationReport(
        JSON.stringify({
          schema_version: 1,
          configured: 1,
          enqueued: 1,
          existing: 0,
          delivered: 1,
          retry_scheduled: 0,
          dead_lettered: 0,
          idle: 0,
          next_retry_at: 1_800_000_000,
        })
      )
    ).toThrow('invalid');
  });

  it('uses the verified binary, exact argv, private pipes, and an allowlisted environment', async () => {
    const binDirectory = await runtimeFixture();
    const fake = fakeChild();
    const spawnProcess = vi.fn(
      (_command: string, _args: readonly string[], _options: SpawnOptions) => {
        const chunks: Buffer[] = [];
        fake.stdin.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        fake.stdin.once('finish', () => {
          const requestFrame = Buffer.concat(chunks);
          expect(requestFrame.subarray(0, 4).toString('ascii')).toBe('ALN1');
          fake.stdout.end(
            JSON.stringify({
              schema_version: 1,
              configured: 1,
              enqueued: 1,
              existing: 0,
              delivered: 1,
              retry_scheduled: 0,
              dead_lettered: 0,
              idle: 0,
              next_retry_at: null,
            })
          );
          fake.process.emit('exit', 0, null);
        });
        return fake.child;
      }
    );

    await expect(
      dispatchAccordLockReviewNotification({
        acceptDirtyDevelopmentMarker: true,
        approvalId: `action:sha256:${'a'.repeat(64)}`,
        baseEnvironment: {
          SystemRoot: 'C:\\Windows',
          AWS_SECRET_ACCESS_KEY: 'must-not-be-inherited',
        },
        binDirectory,
        bundle: dispatchBundle,
        dataDirectory: path.join(binDirectory, 'outbox'),
        expiresAt: 1_800_000_000,
        receivedAt: 1_799_999_700,
        platform: 'win32',
        spawnProcess,
      })
    ).resolves.toMatchObject({ configured: 1, delivered: 1 });

    const [command, args, options] = spawnProcess.mock.calls[0];
    expect(command).toBe(path.join(binDirectory, 'accordlock-agent-runtime.exe'));
    expect(args).toEqual(['notify', '--request-stdio']);
    expect(options).toMatchObject({
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    expect(options.env).toMatchObject({ SystemRoot: 'C:\\Windows' });
    expect(options.env).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
    expect(options.env).not.toHaveProperty('ACCORDLOCK_RUNTIME_TOKEN');
    expect(options.env).toHaveProperty('ACCORDLOCK_NOTIFICATION_DATA_DIR');
  });

  it('kills a stalled process and an oversized response', async () => {
    const binDirectory = await runtimeFixture();
    const stalled = fakeChild();
    await expect(
      dispatchAccordLockReviewNotification({
        acceptDirtyDevelopmentMarker: true,
        approvalId: `action:sha256:${'b'.repeat(64)}`,
        binDirectory,
        bundle: dispatchBundle,
        dataDirectory: path.join(binDirectory, 'stalled'),
        expiresAt: 1_800_000_000,
        receivedAt: 1_799_999_700,
        platform: 'win32',
        spawnProcess: () => stalled.child,
        timeoutMs: 5,
      })
    ).rejects.toThrow('timed out');
    expect(stalled.kill).toHaveBeenCalledWith('SIGKILL');

    const oversized = fakeChild();
    const oversizedDispatch = dispatchAccordLockReviewNotification({
      acceptDirtyDevelopmentMarker: true,
      approvalId: `action:sha256:${'c'.repeat(64)}`,
      binDirectory,
      bundle: dispatchBundle,
      dataDirectory: path.join(binDirectory, 'oversized'),
      expiresAt: 1_800_000_000,
      receivedAt: 1_799_999_700,
      platform: 'win32',
      spawnProcess: () => {
        oversized.stdin.once('finish', () => oversized.stdout.write(Buffer.alloc(4_097, 0x41)));
        return oversized.child;
      },
    });
    await expect(oversizedDispatch).rejects.toThrow('too large');
    expect(oversized.kill).toHaveBeenCalledWith('SIGKILL');
  });

  it('never starts after cancellation and kills an in-flight notifier on cancellation', async () => {
    const binDirectory = await runtimeFixture();
    const alreadyCancelled = new AbortController();
    alreadyCancelled.abort();
    const spawnProcess = vi.fn(() => fakeChild().child);
    await expect(
      dispatchAccordLockReviewNotification({
        acceptDirtyDevelopmentMarker: true,
        approvalId: `action:sha256:${'d'.repeat(64)}`,
        binDirectory,
        bundle: dispatchBundle,
        dataDirectory: path.join(binDirectory, 'cancelled'),
        expiresAt: 1_800_000_000,
        platform: 'win32',
        receivedAt: 1_799_999_700,
        signal: alreadyCancelled.signal,
        spawnProcess,
      })
    ).rejects.toThrow('cancelled');
    expect(spawnProcess).not.toHaveBeenCalled();

    const inFlight = fakeChild();
    const controller = new AbortController();
    const dispatch = dispatchAccordLockReviewNotification({
      acceptDirtyDevelopmentMarker: true,
      approvalId: `action:sha256:${'e'.repeat(64)}`,
      binDirectory,
      bundle: dispatchBundle,
      dataDirectory: path.join(binDirectory, 'in-flight'),
      expiresAt: 1_800_000_000,
      platform: 'win32',
      receivedAt: 1_799_999_700,
      signal: controller.signal,
      spawnProcess: () => inFlight.child,
    });
    controller.abort();
    await expect(dispatch).rejects.toThrow('cancelled');
    expect(inFlight.kill).toHaveBeenCalledWith('SIGKILL');
  });
});
