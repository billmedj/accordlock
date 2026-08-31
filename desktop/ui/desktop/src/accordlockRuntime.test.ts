import type { ChildProcess } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { setImmediate } from 'node:timers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ACCORDLOCK_CONTROL_FRAME_MAGIC,
  ACCORDLOCK_CONTROL_MAX_FRAME_BYTES,
  ACCORDLOCK_GOVERNED_NETWORK_ENV,
  ACCORDLOCK_RUNTIME_MARKER_FILENAME,
  ACCORDLOCK_RUNTIME_TOKEN_ENV,
  ACCORDLOCK_RUNTIME_URL_ENV,
  accordLockFileRestoreChallengeDigest,
  accordLockFileRestoreRecordDigest,
  accordLockObjectiveDigest,
  accordLockRuntimeBinaryName,
  accordLockSessionAuditPageDigest,
  accordLockTaskPolicyDigest,
  buildAccordLockHistoricalAuditLaunchSpec,
  buildAccordLockRuntimeLaunchSpec,
  buildGoosePolicyEnvironment,
  generateAccordLockRuntimeToken,
  parseAccordLockRuntimeReadyLine,
  readAccordLockHistoricalAuditPage,
  resolveAccordLockRuntimeBundle,
  startAccordLockRuntime,
  validateAccordLockRuntimeBuildMarker,
  type ApprovedSession,
  type AccordLockRuntimeBuildMarker,
  type AccordLockRuntimeBundle,
  type AccordLockActionApproval,
  type AccordLockFileRestoreChallenge,
  type SessionRevocation,
} from './accordlockRuntime';
import {
  ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES,
  ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES,
} from './accordlockApprovalProxy';

const tempDirectories: string[] = [];

const makeTempDirectory = (): string => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-runtime-test-'));
  tempDirectories.push(directory);
  return directory;
};

const validMarker = (
  binary: string,
  binarySha256 = 'a'.repeat(64)
): AccordLockRuntimeBuildMarker => ({
  schema_version: 2,
  distribution: 'AccordLock',
  component: 'accordlock-agent-runtime',
  protocol_version: 2,
  source_commit: 'b'.repeat(40),
  source_dirty: false,
  binary,
  binary_sha256: binarySha256,
});

const createRuntimeBundle = (): string => {
  const binDirectory = makeTempDirectory();
  const binary = accordLockRuntimeBinaryName();
  const contents = Buffer.from('verified runtime fixture');
  fs.writeFileSync(path.join(binDirectory, binary), contents);
  fs.writeFileSync(
    path.join(binDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME),
    JSON.stringify(validMarker(binary, createHash('sha256').update(contents).digest('hex')))
  );
  return binDirectory;
};

interface FakeRuntimeProcess {
  child: ChildProcess;
  stdin: PassThrough;
  stdout: PassThrough;
  killedSignals: string[];
}

const createFakeRuntimeProcess = (): FakeRuntimeProcess => {
  const events = new EventEmitter();
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const killedSignals: string[] = [];
  let exited = false;
  const emitExit = (code: number | null, signal: string | null) => {
    if (exited) {
      return;
    }
    exited = true;
    events.emit('exit', code, signal);
    events.emit('close', code, signal);
  };
  const child = Object.assign(events, {
    stdin,
    stdout,
    stderr,
    exitCode: null,
    signalCode: null,
    kill: (signal = 'SIGTERM') => {
      killedSignals.push(signal);
      emitExit(null, signal);
      return true;
    },
  }) as unknown as ChildProcess;
  stdin.once('finish', () => setImmediate(() => emitExit(0, null)));
  return { child, stdin, stdout, killedSignals };
};

const validApproval = (workspaceRoot: string): ApprovedSession => {
  const taskPolicy = {
    schema_version: 2 as const,
    task_objective_hash: accordLockObjectiveDigest('Prepare the exact release notes.'),
    preauthorized_capabilities: [
      { extension_id: 'developer', tool_name: 'read' },
      { extension_id: 'developer', tool_name: 'tree' },
    ],
    protected_paths: ['.git'],
  };
  return {
    schema_version: 3,
    task_id: '12345678-1234-4abc-8def-123456789abc',
    session_id: 'session-1',
    run_id: 'run-1',
    workspace_root: workspaceRoot,
    task_objective: 'Prepare the exact release notes.',
    policy_epoch: 1,
    task_policy: taskPolicy,
    task_policy_hash: accordLockTaskPolicyDigest(taskPolicy),
    capabilities: [
      { extension_id: 'developer', tool_name: 'read' },
      { extension_id: 'developer', tool_name: 'tree' },
      { extension_id: 'developer', tool_name: 'write' },
    ],
    approved_at: 100,
    expires_at: 200,
  };
};

const validRevocation = (): SessionRevocation => ({
  schema_version: 2,
  task_id: '12345678-1234-4abc-8def-123456789abc',
  session_id: 'session-1',
  run_id: 'run-1',
});

const validActionApproval = (taskPolicyHash: string): AccordLockActionApproval => ({
  schema_version: 2,
  approval_id: '33333333-3333-4333-8333-333333333333',
  task_id: '12345678-1234-4abc-8def-123456789abc',
  session_id: 'session-1',
  run_id: 'run-1',
  tool_call_id: 'tool-call-1',
  proposal_digest: `sha256:${'b'.repeat(64)}`,
  task_policy_hash: taskPolicyHash,
  prestate_hash: `sha256:${'c'.repeat(64)}`,
  approval_request_hash: `sha256:${'d'.repeat(64)}`,
  task_requirement: {
    schema_version: 2,
    requirement_id: '44444444-4444-4444-8444-444444444444',
    task_policy_hash: taskPolicyHash,
    statement_hash: `sha256:${'1'.repeat(64)}`,
  },
  transformation_step: {
    schema_version: 2,
    transformation_step_id: '55555555-5555-4555-8555-555555555555',
    task_policy_hash: taskPolicyHash,
    sequence: 0,
    previous_step_hash: null,
    source_stage: 'TASK_REQUEST',
    source_hash: `sha256:${'1'.repeat(64)}`,
    target_stage: 'TOOL_EXECUTION_REQUEST',
    target_hash: `sha256:${'2'.repeat(64)}`,
    recorded_at: 100,
  },
  policy_decision: {
    schema_version: 2,
    policy_decision_id: '66666666-6666-4666-8666-666666666666',
    task_policy_hash: taskPolicyHash,
    action_hash: `sha256:${'2'.repeat(64)}`,
    sequence: 0,
    parent_decision_hash: null,
    task_requirement_hashes: [`sha256:${'3'.repeat(64)}`],
    transformation_step_hashes: [`sha256:${'4'.repeat(64)}`],
    resource_claim_hashes: [],
    resource_capacity_hashes: [],
    resource_reservation_hashes: [],
    baseline: 'ALLOW_AUTOMATIC',
    decision: 'APPROVAL_REQUIRED',
    reasons: ['PROTECTED_WRITE'],
    policy_epoch: 7,
    evaluated_at: 100,
  },
  policy_decision_hash: `sha256:${'5'.repeat(64)}`,
  decision: 'APPROVED',
  approval_evidence_hash: `sha256:${'e'.repeat(64)}`,
  decided_at: 110,
  expires_at: 160,
});

const validRestoreChallenge = (workspaceRoot: string): AccordLockFileRestoreChallenge => ({
  schema_version: 2,
  restore_id: '77777777-7777-4777-8777-777777777777',
  recovery_id: '88888888-8888-4888-8888-888888888888',
  task_id: '12345678-1234-4abc-8def-123456789abc',
  session_id: 'session-1',
  run_id: 'run-1',
  original_record_id: '99999999-9999-4999-8999-999999999999',
  original_record_hash: `sha256:${'9'.repeat(64)}`,
  workspace_root: workspaceRoot,
  relative_path: 'docs/release.md',
  content_sha256: `sha256:${'8'.repeat(64)}`,
  original_bytes: 42,
  prepared_at: 100,
});

const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
};

const approvalDigest = (value: unknown): string =>
  `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;

const controlFrame = (payload: unknown): Buffer => {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const header = Buffer.alloc(8);
  header.write(ACCORDLOCK_CONTROL_FRAME_MAGIC, 0, 'ascii');
  header.writeUInt32BE(body.length, 4);
  return Buffer.concat([header, body]);
};

const decodeControlFrame = (frame: Buffer): Record<string, unknown> => {
  expect(frame.subarray(0, 4).toString('ascii')).toBe(ACCORDLOCK_CONTROL_FRAME_MAGIC);
  const length = frame.readUInt32BE(4);
  expect(frame.length).toBe(8 + length);
  return JSON.parse(frame.subarray(8).toString('utf8')) as Record<string, unknown>;
};

const readyLine = Buffer.from(
  'ACCORDLOCK_RUNTIME_READY={"schema_version":2,"url":"http://127.0.0.1:43127"}\n',
  'ascii'
);

const successfulHealth = async (): Promise<Response> =>
  new Response('{"schema_version":2,"status":"READY"}', {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

afterEach(() => {
  while (tempDirectories.length > 0) {
    const directory = tempDirectories.pop();
    if (directory) {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

describe('AccordLock runtime bundle', () => {
  it('uses one exact platform-specific runtime name', () => {
    expect(accordLockRuntimeBinaryName('win32')).toBe('accordlock-agent-runtime.exe');
    expect(accordLockRuntimeBinaryName('darwin')).toBe('accordlock-agent-runtime');
    expect(accordLockRuntimeBinaryName('linux')).toBe('accordlock-agent-runtime');
  });

  it('accepts an exact clean provenance marker and matching digest', () => {
    const binDirectory = makeTempDirectory();
    const binary = accordLockRuntimeBinaryName();
    const binaryPath = path.join(binDirectory, binary);
    const binaryContents = Buffer.from('verified runtime fixture');
    fs.writeFileSync(binaryPath, binaryContents);
    const digest = createHash('sha256').update(binaryContents).digest('hex');
    fs.writeFileSync(
      path.join(binDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      JSON.stringify(validMarker(binary, digest))
    );

    const resolved = resolveAccordLockRuntimeBundle(binDirectory);

    expect(resolved.binaryPath).toBe(binaryPath);
    expect(resolved.marker.binary_sha256).toBe(digest);
  });

  it('rejects a digest mismatch', () => {
    const binDirectory = makeTempDirectory();
    const binary = accordLockRuntimeBinaryName();
    fs.writeFileSync(path.join(binDirectory, binary), 'different bytes');
    fs.writeFileSync(
      path.join(binDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      JSON.stringify(validMarker(binary))
    );

    expect(() => resolveAccordLockRuntimeBundle(binDirectory)).toThrow('digest mismatch');
  });

  it('rejects a runtime marker that is not anchored to the application bundle', () => {
    const binDirectory = makeTempDirectory();
    const binary = accordLockRuntimeBinaryName();
    const binaryContents = Buffer.from('verified runtime fixture');
    fs.writeFileSync(path.join(binDirectory, binary), binaryContents);
    const digest = createHash('sha256').update(binaryContents).digest('hex');
    fs.writeFileSync(
      path.join(binDirectory, ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      JSON.stringify(validMarker(binary, digest))
    );

    expect(() =>
      resolveAccordLockRuntimeBundle(binDirectory, process.platform, false, 'f'.repeat(64))
    ).toThrow('does not match the embedded application digest');
  });

  it('rejects dirty provenance and unknown marker fields', () => {
    const binary = accordLockRuntimeBinaryName();
    expect(() =>
      validateAccordLockRuntimeBuildMarker({ ...validMarker(binary), source_dirty: true }, binary)
    ).toThrow('clean source tree');
    expect(() =>
      validateAccordLockRuntimeBuildMarker({ ...validMarker(binary), extra: true }, binary)
    ).toThrow('missing or unexpected');
  });

  it('allows an explicitly declared dirty marker only through the development gate', () => {
    const binary = accordLockRuntimeBinaryName();
    const dirtyMarker = { ...validMarker(binary), source_dirty: true };

    expect(validateAccordLockRuntimeBuildMarker(dirtyMarker, binary, true).source_dirty).toBe(true);
    expect(() => validateAccordLockRuntimeBuildMarker(dirtyMarker, binary)).toThrow(
      'clean source tree'
    );
  });

  it('allows the zero-commit sentinel only for an explicitly dirty development marker', () => {
    const binary = accordLockRuntimeBinaryName();
    const cleanSentinel = { ...validMarker(binary), source_commit: '0'.repeat(40) };
    const dirtySentinel = { ...cleanSentinel, source_dirty: true };

    expect(() => validateAccordLockRuntimeBuildMarker(cleanSentinel, binary)).toThrow(
      'zero source commit sentinel'
    );
    expect(() => validateAccordLockRuntimeBuildMarker(cleanSentinel, binary, true)).toThrow(
      'zero source commit sentinel'
    );
    expect(() => validateAccordLockRuntimeBuildMarker(dirtySentinel, binary)).toThrow(
      'clean source tree'
    );
    expect(validateAccordLockRuntimeBuildMarker(dirtySentinel, binary, true).source_commit).toBe(
      '0'.repeat(40)
    );
  });
});

describe('AccordLock runtime launch contract', () => {
  it('keeps the token out of arguments and replaces inherited authority', () => {
    const token = 'A'.repeat(43);
    const binaryPath = path.resolve(accordLockRuntimeBinaryName());
    const bundle: AccordLockRuntimeBundle = {
      binaryPath,
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(path.basename(binaryPath)),
    };

    const launch = buildAccordLockRuntimeLaunchSpec(bundle, token, './runtime-data', {
      [ACCORDLOCK_RUNTIME_URL_ENV]: 'http://127.0.0.1:1',
      [ACCORDLOCK_RUNTIME_TOKEN_ENV]: 'untrusted-existing-token',
      OPENAI_API_KEY: 'provider-secret',
      ANTHROPIC_API_KEY: 'provider-secret',
      GOOSE_PROVIDER_SECRET: 'goose-secret',
      PATH: 'unnecessary-for-an-exact-binary',
      TEMP: 'C:\\safe-temp',
    });

    expect(launch.command).toBe(binaryPath);
    expect(launch.args).toEqual([
      'serve',
      '--host',
      '127.0.0.1',
      '--port',
      '0',
      '--ready-line',
      '--control-stdio',
    ]);
    expect(launch.options.stdio).toEqual(['pipe', 'pipe', 'pipe']);
    expect(launch.args.join(' ')).not.toContain(token);
    expect(launch.options.env?.[ACCORDLOCK_RUNTIME_URL_ENV]).toBeUndefined();
    expect(launch.options.env?.[ACCORDLOCK_RUNTIME_TOKEN_ENV]).toBe(token);
    expect(launch.options.env?.OPENAI_API_KEY).toBeUndefined();
    expect(launch.options.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(launch.options.env?.GOOSE_PROVIDER_SECRET).toBeUndefined();
    expect(launch.options.env?.PATH).toBeUndefined();
    expect(launch.options.env?.TEMP).toBe('C:\\safe-temp');
  });

  it('generates distinct 256-bit base64url launch tokens', () => {
    const first = generateAccordLockRuntimeToken();
    const second = generateAccordLockRuntimeToken();

    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second).not.toBe(first);
  });

  it('launches historical audit without inheriting execution authority or provider secrets', () => {
    const binaryPath = path.resolve(accordLockRuntimeBinaryName());
    const dataDirectory = path.resolve('historical-runtime-data');
    const bundle: AccordLockRuntimeBundle = {
      binaryPath,
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(path.basename(binaryPath)),
    };
    const launch = buildAccordLockHistoricalAuditLaunchSpec(bundle, dataDirectory, {
      [ACCORDLOCK_RUNTIME_URL_ENV]: 'http://127.0.0.1:1',
      [ACCORDLOCK_RUNTIME_TOKEN_ENV]: 'old-execution-authority',
      OPENAI_API_KEY: 'provider-secret',
      PATH: 'not-required-for-an-exact-binary',
      TEMP: 'C:\\safe-temp',
    });

    expect(launch.command).toBe(binaryPath);
    expect(launch.args).toEqual(['audit', '--control-stdio']);
    expect(launch.options).toMatchObject({
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    expect(launch.options.env).toEqual({
      ACCORDLOCK_RUNTIME_DATA_DIR: dataDirectory,
      TEMP: 'C:\\safe-temp',
    });
    expect(launch.options.env?.[ACCORDLOCK_RUNTIME_TOKEN_ENV]).toBeUndefined();
    expect(launch.options.env?.[ACCORDLOCK_RUNTIME_URL_ENV]).toBeUndefined();
    expect(launch.options.env?.OPENAI_API_KEY).toBeUndefined();
    expect(() =>
      buildAccordLockHistoricalAuditLaunchSpec(bundle, 'relative-ledger-directory', {})
    ).toThrow('must be absolute');
  });

  it('passes sorted digest-pinned terminal aliases as argv-only runtime bindings', () => {
    const token = 'A'.repeat(43);
    const binaryPath = path.resolve(accordLockRuntimeBinaryName());
    const bundle: AccordLockRuntimeBundle = {
      binaryPath,
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(path.basename(binaryPath)),
    };
    const alpha = path.resolve('alpha-probe.exe');
    const zeta = path.resolve('zeta-probe.exe');
    const launch = buildAccordLockRuntimeLaunchSpec(bundle, token, './runtime-data', {}, [
      { alias: 'zeta', executable_path: zeta, executable_sha256: `sha256:${'2'.repeat(64)}` },
      { alias: 'alpha', executable_path: alpha, executable_sha256: `sha256:${'1'.repeat(64)}` },
    ]);

    expect(launch.options.shell).toBe(false);
    expect(launch.args.slice(-4)).toEqual([
      '--terminal-program',
      `alpha=sha256:${'1'.repeat(64)}=${alpha}`,
      '--terminal-program',
      `zeta=sha256:${'2'.repeat(64)}=${zeta}`,
    ]);
  });

  it('rejects duplicate or malformed terminal launch bindings', () => {
    const bundle: AccordLockRuntimeBundle = {
      binaryPath: path.resolve(accordLockRuntimeBinaryName()),
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(accordLockRuntimeBinaryName()),
    };
    const executable = path.resolve('probe.exe');
    const binding = {
      alias: 'probe',
      executable_path: executable,
      executable_sha256: `sha256:${'1'.repeat(64)}`,
    } as const;

    expect(() =>
      buildAccordLockRuntimeLaunchSpec(bundle, 'A'.repeat(43), './runtime-data', {}, [
        binding,
        binding,
      ])
    ).toThrow('malformed or duplicated');
    expect(() =>
      buildAccordLockRuntimeLaunchSpec(bundle, 'A'.repeat(43), './runtime-data', {}, [
        { ...binding, executable_sha256: `sha256:${'G'.repeat(64)}` },
      ])
    ).toThrow('malformed or duplicated');
  });

  it('passes only sorted exact HTTPS domains as repeatable runtime arguments', () => {
    const binaryPath = path.resolve(accordLockRuntimeBinaryName());
    const bundle: AccordLockRuntimeBundle = {
      binaryPath,
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(path.basename(binaryPath)),
    };
    const launch = buildAccordLockRuntimeLaunchSpec(
      bundle,
      'A'.repeat(43),
      './runtime-data',
      {},
      [],
      ['status.example.com', 'api.example.com']
    );

    expect(launch.args.slice(-4)).toEqual([
      '--https-domain',
      'api.example.com',
      '--https-domain',
      'status.example.com',
    ]);
  });

  it.each([
    ['duplicate', ['api.example.com', 'api.example.com']],
    ['wildcard', ['*.example.com']],
    ['URL', ['https://api.example.com']],
    ['IPv4 literal', ['127.0.0.1']],
    ['localhost-like name', ['api.localhost']],
    ['explicit port', ['api.example.com:443']],
  ])('rejects a %s controlled network launch policy', (_label, domains) => {
    const binaryPath = path.resolve(accordLockRuntimeBinaryName());
    const bundle: AccordLockRuntimeBundle = {
      binaryPath,
      markerPath: path.resolve(ACCORDLOCK_RUNTIME_MARKER_FILENAME),
      marker: validMarker(path.basename(binaryPath)),
    };

    expect(() =>
      buildAccordLockRuntimeLaunchSpec(bundle, 'A'.repeat(43), './runtime-data', {}, [], domains)
    ).toThrow('malformed or duplicated');
  });

  it('builds the only two environment entries exposed to Goose', () => {
    const environment = buildGoosePolicyEnvironment('http://127.0.0.1:43127', 'A'.repeat(43));

    expect(environment).toEqual({
      [ACCORDLOCK_RUNTIME_URL_ENV]: 'http://127.0.0.1:43127',
      [ACCORDLOCK_RUNTIME_TOKEN_ENV]: 'A'.repeat(43),
    });
    expect(Object.isFrozen(environment)).toBe(true);
  });

  it('exposes the controlled network marker to Goose only when startup policy is active', () => {
    const disabled = buildGoosePolicyEnvironment('http://127.0.0.1:43127', 'A'.repeat(43), false);
    const enabled = buildGoosePolicyEnvironment('http://127.0.0.1:43127', 'A'.repeat(43), true);

    expect(disabled[ACCORDLOCK_GOVERNED_NETWORK_ENV]).toBeUndefined();
    expect(enabled[ACCORDLOCK_GOVERNED_NETWORK_ENV]).toBe('1');
    expect(Object.keys(enabled).sort()).toEqual(
      [
        ACCORDLOCK_GOVERNED_NETWORK_ENV,
        ACCORDLOCK_RUNTIME_TOKEN_ENV,
        ACCORDLOCK_RUNTIME_URL_ENV,
      ].sort()
    );
  });

  it('accepts only a strict ephemeral IPv4 loopback ready line', () => {
    expect(
      parseAccordLockRuntimeReadyLine(
        'ACCORDLOCK_RUNTIME_READY={"schema_version":2,"url":"http://127.0.0.1:43127"}'
      )
    ).toBe('http://127.0.0.1:43127');
    expect(parseAccordLockRuntimeReadyLine('ordinary runtime output')).toBeNull();
    expect(() =>
      parseAccordLockRuntimeReadyLine(
        'ACCORDLOCK_RUNTIME_READY={"schema_version":2,"url":"http://localhost:43127"}'
      )
    ).toThrow('IPv4 loopback');
    expect(() =>
      parseAccordLockRuntimeReadyLine(
        'ACCORDLOCK_RUNTIME_READY={"schema_version":2,"url":"http://127.0.0.1:43127","token":"leak"}'
      )
    ).toThrow('incompatible');
  });
});

describe('AccordLock private control channel', () => {
  it('matches the Rust v2 domain-separated restore hash golden vectors', () => {
    const challenge = validRestoreChallenge('/srv/accordlock/project');
    const challengeHash = accordLockFileRestoreChallengeDigest(challenge);
    expect(challengeHash).toBe(
      'sha256:40b527525edeff9a72cb2a2dcbe03acf1431c46bc751a9740e517f5c93afb095'
    );

    const record = {
      schema_version: 2,
      restore_id: challenge.restore_id,
      recovery_id: challenge.recovery_id,
      challenge_hash: challengeHash,
      task_id: challenge.task_id,
      session_id: challenge.session_id,
      run_id: challenge.run_id,
      original_record_id: challenge.original_record_id,
      original_record_hash: challenge.original_record_hash,
      workspace_root: challenge.workspace_root,
      relative_path: challenge.relative_path,
      content_sha256: challenge.content_sha256,
      original_bytes: challenge.original_bytes,
      completed_at: 120,
    } as const;
    expect(accordLockFileRestoreRecordDigest(record)).toBe(
      'sha256:27d5f9cbf8b3fe864e66ed7fadc123f141e923a7607c3131d134be53fcf87d06'
    );
  });

  it('matches the Rust v6 audit-page digest golden vector', () => {
    expect(
      accordLockSessionAuditPageDigest({
        schema_version: 6,
        task_id: '12345678-1234-4abc-8def-123456789abc',
        session_id: 'session-1',
        run_id: 'run-1',
        offset: 0,
        next_offset: 1,
        total_events: 2,
        snapshot_revision: 17,
        snapshot_at: 120,
        events: [
          {
            type: 'ACTION_DENIED',
            event_id: 'action-denied:42',
            recorded_at: 119,
            denial_id: 42,
            attempted_run_id: 'run-1',
            tool_call_id: 'call-1',
            proposal_digest: `sha256:${'a'.repeat(64)}`,
            reason_code: 'CAPABILITY_NOT_APPROVED',
          },
        ],
      })
    ).toBe('sha256:97700bb686a5841ffd3869397cbaf1085ecd1c5e4272d87ba5a9abdcceb19cd5');
  });

  it('forwards proxy requests with the hidden runtime bearer and preserves exact bytes', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimeFetch = vi
      .fn()
      .mockResolvedValueOnce(await successfulHealth())
      .mockResolvedValueOnce(
        new Response(Buffer.from([0, 255, 7]), {
          status: 202,
          headers: { 'Content-Type': 'application/octet-stream' },
        })
      );
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: runtimeFetch,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const requestBody = Buffer.from('{"exact":true}', 'utf8');

    const response = await runtime.forwardPolicyRequest(
      '/api/v2/execution/filesystem/authorize-and-execute',
      'POST',
      requestBody
    );

    expect(response).toEqual({
      status: 202,
      contentType: 'application/octet-stream',
      body: new Uint8Array([0, 255, 7]),
    });
    const [url, init] = runtimeFetch.mock.calls[1] as [
      string,
      NonNullable<Parameters<typeof fetch>[1]>,
    ];
    expect(url).toBe('http://127.0.0.1:43127/api/v2/execution/filesystem/authorize-and-execute');
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({
      Authorization: `Bearer ${'A'.repeat(43)}`,
      'Content-Type': 'application/json',
    });
    expect(Buffer.from(init.body as Uint8Array)).toEqual(requestBody);
    await runtime.cleanup();
  });

  it('uses the terminal-specific 8 MiB response bound without widening requests', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const exactResponse = Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES, 7);
    const terminalArguments = { argv: ['probe'], timeout_seconds: 300 };
    const terminalRequest = Buffer.from(
      JSON.stringify({
        schema_version: 2,
        proposal: {
          schema_version: 2,
          session_id: 'session-1',
          run_id: 'run-1',
          tool_call_id: 'tool-call-1',
          workspace_root: path.resolve(binDirectory),
          extension_id: 'developer',
          tool_name: 'shell',
          arguments: terminalArguments,
          arguments_sha256: approvalDigest(terminalArguments),
        },
      }),
      'utf8'
    );
    const streamedOverflow = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          new Uint8Array(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES / 2)
        );
        controller.enqueue(
          new Uint8Array(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES / 2 + 1)
        );
        controller.close();
      },
    });
    const runtimeFetch = vi
      .fn()
      .mockResolvedValueOnce(await successfulHealth())
      .mockResolvedValueOnce(
        new Response(exactResponse, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        })
      )
      .mockResolvedValueOnce(
        new Response(Buffer.alloc(0), {
          status: 200,
          headers: {
            'Content-Length': String(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES + 1),
          },
        })
      )
      .mockResolvedValueOnce(new Response(streamedOverflow, { status: 200 }))
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const timeoutSpy = vi.spyOn(globalThis.AbortSignal, 'timeout');
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: runtimeFetch,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const terminalPath = '/api/v2/execution/terminal/authorize-and-execute';

    const exact = await runtime.forwardPolicyRequest(terminalPath, 'POST', terminalRequest);
    expect(exact.body).toHaveLength(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES);
    await expect(
      runtime.forwardPolicyRequest(terminalPath, 'POST', terminalRequest)
    ).rejects.toThrow('bounded profile');
    await expect(
      runtime.forwardPolicyRequest(terminalPath, 'POST', terminalRequest)
    ).rejects.toThrow('bounded profile');
    await expect(
      runtime.forwardPolicyRequest(
        terminalPath,
        'POST',
        Buffer.from('{"timeout_seconds":999999999}', 'utf8')
      )
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      runtime.forwardPolicyRequest(
        terminalPath,
        'POST',
        Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES + 1)
      )
    ).rejects.toThrow('bounded profile');
    expect(timeoutSpy.mock.calls.map(([milliseconds]) => milliseconds)).toEqual([
      330_000, 330_000, 330_000, 330_000,
    ]);
    expect(runtimeFetch).toHaveBeenCalledTimes(5);
    await runtime.cleanup();
  });

  it('preserves post-readiness bytes and approves one canonical session', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const starting = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    });
    fake.stdout.write(readyLine.subarray(0, 17));
    fake.stdout.write(readyLine.subarray(17));
    const runtime = await starting;

    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const approvedSession = validApproval(path.resolve(binDirectory));
    const approval = runtime.authorizeTask(approvedSession);
    const request = decodeControlFrame(await outbound);
    expect(request).toEqual({
      schema_version: 2,
      request_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      method: 'APPROVE_SESSION',
      approved_session: approvedSession,
    });

    const response = controlFrame({
      schema_version: 2,
      request_id: request.request_id,
      status: 'ACK',
      code: 'SESSION_APPROVED',
      approval_digest: approvalDigest(approvedSession),
    });
    fake.stdout.write(response.subarray(0, 3));
    fake.stdout.write(response.subarray(3, 11));
    fake.stdout.write(response.subarray(11));

    await expect(approval).resolves.toEqual({
      requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      code: 'SESSION_APPROVED',
      approvalDigest: approvalDigest(approvedSession),
    });
    await runtime.cleanup();
    expect(fake.stdin.writableEnded).toBe(true);
    expect(fake.killedSignals).toEqual([]);
  });

  it('serializes approval and policy approval frames on the private control pipe', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const requestIds = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222',
    ];
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => requestIds.shift() ?? randomUUID(),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approvedSession = validApproval(path.resolve(binDirectory));
    const actionApproval = validActionApproval(approvedSession.task_policy_hash);

    let outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const sessionAuthorization = runtime.authorizeTask(approvedSession);
    const actionRegistration = runtime.registerActionApproval(actionApproval);
    const sessionAuthorizationRequest = decodeControlFrame(await outbound);
    expect(sessionAuthorizationRequest.method).toBe('APPROVE_SESSION');

    outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: sessionAuthorizationRequest.request_id,
        status: 'ACK',
        code: 'SESSION_APPROVED',
        approval_digest: approvalDigest(approvedSession),
      })
    );
    await expect(sessionAuthorization).resolves.toBeDefined();
    const actionApprovalRequest = decodeControlFrame(await outbound);
    expect(actionApprovalRequest.method).toBe('REGISTER_ACTION_APPROVAL');
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: actionApprovalRequest.request_id,
        status: 'ACK',
        code: 'ACTION_APPROVAL_REGISTERED',
        approval_digest: approvalDigest(actionApproval),
        approval_id: actionApproval.approval_id,
        proposal_digest: actionApproval.proposal_digest,
        approval_request_hash: actionApproval.approval_request_hash,
      })
    );
    await expect(actionRegistration).resolves.toBeDefined();
    await runtime.cleanup();
  });

  it('revokes one exact authority and accepts only a digest-and-identity-bound acknowledgement', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const requestIds = [
      'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    ];
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => requestIds.shift() ?? 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const revocation = validRevocation();

    let outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const firstRevocation = runtime.revokeSession(revocation);
    let request = decodeControlFrame(await outbound);
    expect(request).toEqual({
      schema_version: 2,
      request_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      method: 'REVOKE_SESSION',
      session_revocation: revocation,
    });
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: request.request_id,
        status: 'ACK',
        code: 'SESSION_REVOKED',
        revocation_digest: approvalDigest(revocation),
        task_id: revocation.task_id,
        session_id: revocation.session_id,
        run_id: revocation.run_id,
      })
    );
    await expect(firstRevocation).resolves.toEqual({
      requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      code: 'SESSION_REVOKED',
      revocationDigest: approvalDigest(revocation),
      taskId: revocation.task_id,
      sessionId: revocation.session_id,
      runId: revocation.run_id,
    });

    outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const retry = runtime.revokeSession(revocation);
    request = decodeControlFrame(await outbound);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: request.request_id,
        status: 'ACK',
        code: 'SESSION_ALREADY_REVOKED',
        revocation_digest: approvalDigest(revocation),
        task_id: revocation.task_id,
        session_id: revocation.session_id,
        run_id: revocation.run_id,
      })
    );
    await expect(retry).resolves.toMatchObject({
      requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      code: 'SESSION_ALREADY_REVOKED',
      revocationDigest: approvalDigest(revocation),
    });
    expect(fake.killedSignals).toEqual([]);
    await runtime.cleanup();
  });

  it('reads only digest-bound bounded audit pages through the private control pipe', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => '45454545-4545-4545-8545-454545454545',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approved = validApproval(path.resolve(binDirectory));

    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const reading = runtime.getSessionAudit(approved.session_id, 0, 10);
    const request = decodeControlFrame(await outbound);
    expect(request).toEqual({
      schema_version: 2,
      request_id: '45454545-4545-4545-8545-454545454545',
      method: 'GET_SESSION_AUDIT',
      audit_query: {
        schema_version: 2,
        session_id: approved.session_id,
        offset: 0,
        limit: 10,
        snapshot_revision: null,
      },
    });
    const events = [
      {
        type: 'ACTION_DENIED',
        event_id: 'action-denied:1',
        recorded_at: 121,
        denial_id: 1,
        attempted_run_id: approved.run_id,
        tool_call_id: 'tool-call-1',
        proposal_digest: `sha256:${'3'.repeat(64)}`,
        reason_code: 'CAPABILITY_NOT_APPROVED',
      },
      {
        type: 'SESSION_APPROVED',
        event_id: `session-approved:sha256:${'4'.repeat(64)}`,
        recorded_at: 100,
        task_id: approved.task_id,
        run_id: approved.run_id,
        workspace_root: approved.workspace_root,
        policy_hash: approved.task_policy_hash,
        expires_at: approved.expires_at,
      },
    ] as const;
    const pageWithoutDigest = {
      schema_version: 6,
      task_id: approved.task_id,
      session_id: approved.session_id,
      run_id: approved.run_id,
      offset: 0,
      next_offset: null,
      total_events: 2,
      snapshot_revision: 17,
      snapshot_at: 121,
      events: [...events],
    } as const;
    const page = {
      ...pageWithoutDigest,
      page_digest: accordLockSessionAuditPageDigest(pageWithoutDigest),
    };
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: request.request_id,
        status: 'ACK',
        code: 'SESSION_AUDIT_READY',
        page,
      })
    );

    await expect(reading).resolves.toEqual(page);
    await expect(runtime.getSessionAudit(approved.session_id, 1, 10)).rejects.toThrow(
      'outside the bounded profile'
    );
    expect(JSON.stringify(page)).not.toContain('arguments');
    expect(fake.killedSignals).toEqual([]);
    await runtime.cleanup();
  });

  it('reads a stopped ledger through one authority-free audit process and verifies its binding', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const approved = {
      ...validApproval(path.resolve(binDirectory)),
      run_id: `sha256:${'8'.repeat(64)}`,
    };
    const requestId = '67676767-6767-4767-8767-676767676767';
    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const reading = readAccordLockHistoricalAuditPage({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      expectedTaskId: approved.task_id,
      expectedSessionId: approved.session_id,
      expectedRunId: approved.run_id,
      offset: 0,
      limit: 10,
      snapshotRevision: null,
      logger: { info: () => {}, error: () => {} },
      spawnProcess: () => fake.child,
      controlRequestIdFactory: () => requestId,
    });
    const request = decodeControlFrame(await outbound);
    expect(request).toEqual({
      schema_version: 2,
      request_id: requestId,
      method: 'GET_SESSION_AUDIT',
      audit_query: {
        schema_version: 2,
        session_id: approved.session_id,
        offset: 0,
        limit: 10,
        snapshot_revision: null,
      },
    });
    const pageWithoutDigest = {
      schema_version: 6 as const,
      task_id: approved.task_id,
      session_id: approved.session_id,
      run_id: approved.run_id,
      offset: 0,
      next_offset: null,
      total_events: 1,
      snapshot_revision: 31,
      snapshot_at: approved.approved_at,
      events: [
        {
          type: 'SESSION_APPROVED' as const,
          event_id: `session-approved:sha256:${'4'.repeat(64)}`,
          recorded_at: approved.approved_at,
          task_id: approved.task_id,
          run_id: approved.run_id,
          workspace_root: approved.workspace_root,
          policy_hash: approved.task_policy_hash,
          expires_at: approved.expires_at,
        },
      ],
    };
    const page = {
      ...pageWithoutDigest,
      page_digest: accordLockSessionAuditPageDigest(pageWithoutDigest),
    };
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: requestId,
        status: 'ACK',
        code: 'SESSION_AUDIT_READY',
        page,
      })
    );

    await expect(reading).resolves.toEqual(page);
    expect(fake.killedSignals).toEqual([]);
  });

  it('fails closed when a historical ledger reports an unknown session', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const requestId = '78787878-7878-4787-8787-787878787878';
    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const reading = readAccordLockHistoricalAuditPage({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      expectedTaskId: '12345678-1234-4abc-8def-123456789abc',
      expectedSessionId: 'missing-session',
      expectedRunId: `sha256:${'8'.repeat(64)}`,
      offset: 0,
      limit: 10,
      snapshotRevision: null,
      logger: { info: () => {}, error: () => {} },
      spawnProcess: () => fake.child,
      controlRequestIdFactory: () => requestId,
    });
    await outbound;
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: requestId,
        status: 'ERROR',
        code: 'UNKNOWN_SESSION',
        page: null,
      })
    );

    await expect(reading).rejects.toThrow('audit query rejected: UNKNOWN_SESSION');
    expect(fake.killedSignals).toEqual([]);
  });

  it('closes the private channel when an audit page is tampered', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const onUnexpectedExit = vi.fn();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => '56565656-5656-4656-8656-565656565656',
      onUnexpectedExit,
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approved = validApproval(path.resolve(binDirectory));
    const pending = runtime.getSessionAudit(approved.session_id, 0, 10);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: '56565656-5656-4656-8656-565656565656',
        status: 'ACK',
        code: 'SESSION_AUDIT_READY',
        page: {
          schema_version: 6,
          task_id: approved.task_id,
          session_id: approved.session_id,
          run_id: approved.run_id,
          offset: 0,
          next_offset: null,
          total_events: 1,
          snapshot_revision: 17,
          snapshot_at: 100,
          events: [
            {
              type: 'SESSION_APPROVED',
              event_id: `session-approved:sha256:${'4'.repeat(64)}`,
              recorded_at: 100,
              task_id: approved.task_id,
              run_id: approved.run_id,
              workspace_root: approved.workspace_root,
              policy_hash: approved.task_policy_hash,
              expires_at: approved.expires_at,
            },
          ],
          page_digest: `sha256:${'f'.repeat(64)}`,
        },
      })
    );

    await expect(pending).rejects.toThrow('digest does not match');
    await expect(runtime.getSessionAudit(approved.session_id)).rejects.toThrow(
      'digest does not match'
    );
    expect(onUnexpectedExit).toHaveBeenCalledOnce();
    await runtime.cleanup();
  });

  it('registers one exact policy approval only through the private ALC1 channel', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'abababab-abab-4bab-8bab-abababababab',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approvedSession = validApproval(path.resolve(binDirectory));
    const actionApproval = validActionApproval(approvedSession.task_policy_hash);

    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const registration = runtime.registerActionApproval(actionApproval);
    const request = decodeControlFrame(await outbound);
    expect(request).toEqual({
      schema_version: 2,
      request_id: 'abababab-abab-4bab-8bab-abababababab',
      method: 'REGISTER_ACTION_APPROVAL',
      action_approval: actionApproval,
    });
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: request.request_id,
        status: 'ACK',
        code: 'ACTION_APPROVAL_REGISTERED',
        approval_digest: approvalDigest(actionApproval),
        approval_id: actionApproval.approval_id,
        proposal_digest: actionApproval.proposal_digest,
        approval_request_hash: actionApproval.approval_request_hash,
      })
    );

    await expect(registration).resolves.toEqual({
      requestId: 'abababab-abab-4bab-8bab-abababababab',
      code: 'ACTION_APPROVAL_REGISTERED',
      approvalDigest: approvalDigest(actionApproval),
      approvalId: actionApproval.approval_id,
      proposalDigest: actionApproval.proposal_digest,
      approvalRequestHash: actionApproval.approval_request_hash,
    });
    expect(fake.killedSignals).toEqual([]);
    await runtime.cleanup();
  });

  it('prepares and commits one exact file restore only through the private control pipe', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const requestIds = [
      '12121212-1212-4212-8212-121212121212',
      '34343434-3434-4434-8434-343434343434',
    ];
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => requestIds.shift() ?? randomUUID(),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const challenge = validRestoreChallenge(path.resolve(binDirectory));
    const challengeHash = accordLockFileRestoreChallengeDigest(challenge);

    let outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const preparing = runtime.prepareFileRestore(challenge.recovery_id);
    const prepareRequest = decodeControlFrame(await outbound);
    expect(prepareRequest).toEqual({
      schema_version: 2,
      request_id: '12121212-1212-4212-8212-121212121212',
      method: 'PREPARE_FILE_RESTORE',
      file_restore_prepare: {
        schema_version: 2,
        recovery_id: challenge.recovery_id,
      },
    });
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: prepareRequest.request_id,
        status: 'ACK',
        code: 'FILE_RESTORE_PREPARED',
        challenge_hash: challengeHash,
        challenge,
        record_hash: null,
        record: null,
      })
    );
    await expect(preparing).resolves.toEqual({
      requestId: '12121212-1212-4212-8212-121212121212',
      code: 'FILE_RESTORE_PREPARED',
      challengeHash,
      challenge,
    });

    outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const committing = runtime.commitFileRestore(challenge);
    const commitRequest = decodeControlFrame(await outbound);
    expect(commitRequest).toEqual({
      schema_version: 2,
      request_id: '34343434-3434-4434-8434-343434343434',
      method: 'COMMIT_FILE_RESTORE',
      file_restore_commit: {
        schema_version: 2,
        restore_id: challenge.restore_id,
        recovery_id: challenge.recovery_id,
        challenge_hash: challengeHash,
      },
    });
    const record = {
      schema_version: 2,
      restore_id: challenge.restore_id,
      recovery_id: challenge.recovery_id,
      challenge_hash: challengeHash,
      task_id: challenge.task_id,
      session_id: challenge.session_id,
      run_id: challenge.run_id,
      original_record_id: challenge.original_record_id,
      original_record_hash: challenge.original_record_hash,
      workspace_root: challenge.workspace_root,
      relative_path: challenge.relative_path,
      content_sha256: challenge.content_sha256,
      original_bytes: challenge.original_bytes,
      completed_at: 120,
    } as const;
    const recordHash = accordLockFileRestoreRecordDigest(record);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: commitRequest.request_id,
        status: 'ACK',
        code: 'FILE_RESTORE_COMMITTED',
        challenge_hash: challengeHash,
        challenge: null,
        record_hash: recordHash,
        record,
      })
    );
    await expect(committing).resolves.toEqual({
      requestId: '34343434-3434-4434-8434-343434343434',
      code: 'FILE_RESTORE_COMMITTED',
      challengeHash,
      recordHash,
      record,
    });
    expect(fake.killedSignals).toEqual([]);
    await runtime.cleanup();
  });

  it('fails closed on a legacy undomained restore challenge hash', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => '45454545-4545-4545-8545-454545454545',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const challenge = validRestoreChallenge('/srv/accordlock/project');

    const outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const preparing = runtime.prepareFileRestore(challenge.recovery_id);
    const request = decodeControlFrame(await outbound);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: request.request_id,
        status: 'ACK',
        code: 'FILE_RESTORE_PREPARED',
        challenge_hash: approvalDigest(challenge),
        challenge,
        record_hash: null,
        record: null,
      })
    );

    await expect(preparing).rejects.toThrow(
      'AccordLock file restore challenge hash does not match its content'
    );
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('fails closed on a legacy undomained restore record hash', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const requestIds = [
      '56565656-5656-4656-8656-565656565656',
      '67676767-6767-4767-8767-676767676767',
    ];
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => requestIds.shift() ?? randomUUID(),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const challenge = validRestoreChallenge('/srv/accordlock/project');
    const challengeHash = accordLockFileRestoreChallengeDigest(challenge);

    let outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const preparing = runtime.prepareFileRestore(challenge.recovery_id);
    const prepareRequest = decodeControlFrame(await outbound);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: prepareRequest.request_id,
        status: 'ACK',
        code: 'FILE_RESTORE_PREPARED',
        challenge_hash: challengeHash,
        challenge,
        record_hash: null,
        record: null,
      })
    );
    await preparing;

    outbound = new Promise<Buffer>((resolve) => fake.stdin.once('data', resolve));
    const committing = runtime.commitFileRestore(challenge);
    const commitRequest = decodeControlFrame(await outbound);
    const record = {
      schema_version: 2,
      restore_id: challenge.restore_id,
      recovery_id: challenge.recovery_id,
      challenge_hash: challengeHash,
      task_id: challenge.task_id,
      session_id: challenge.session_id,
      run_id: challenge.run_id,
      original_record_id: challenge.original_record_id,
      original_record_hash: challenge.original_record_hash,
      workspace_root: challenge.workspace_root,
      relative_path: challenge.relative_path,
      content_sha256: challenge.content_sha256,
      original_bytes: challenge.original_bytes,
      completed_at: 120,
    } as const;
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: commitRequest.request_id,
        status: 'ACK',
        code: 'FILE_RESTORE_COMMITTED',
        challenge_hash: challengeHash,
        challenge: null,
        record_hash: approvalDigest(record),
        record,
      })
    );

    await expect(committing).rejects.toThrow(
      'AccordLock file restore record hash does not match its content'
    );
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('terminates if a policy approval acknowledgement is rebound to another context', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const actionApproval = validActionApproval(
      validApproval(path.resolve(binDirectory)).task_policy_hash
    );
    const pending = runtime.registerActionApproval(actionApproval);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd',
        status: 'ACK',
        code: 'ACTION_APPROVAL_REGISTERED',
        approval_digest: approvalDigest(actionApproval),
        approval_id: actionApproval.approval_id,
        proposal_digest: actionApproval.proposal_digest,
        approval_request_hash: `sha256:${'f'.repeat(64)}`,
      })
    );

    await expect(pending).rejects.toThrow('identity or digest does not match');
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('fails closed when a revocation acknowledgement echoes a different identity', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const revocation = validRevocation();
    const pending = runtime.revokeSession(revocation);
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
        status: 'ACK',
        code: 'SESSION_REVOKED',
        revocation_digest: approvalDigest(revocation),
        task_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        session_id: revocation.session_id,
        run_id: revocation.run_id,
      })
    );

    await expect(pending).rejects.toThrow('identity or digest does not match');
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('rejects and terminates on a malformed or oversized response', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approval = runtime.authorizeTask(validApproval(path.resolve(binDirectory)));
    const header = Buffer.alloc(8);
    header.write(ACCORDLOCK_CONTROL_FRAME_MAGIC, 0, 'ascii');
    header.writeUInt32BE(ACCORDLOCK_CONTROL_MAX_FRAME_BYTES + 1, 4);
    fake.stdout.write(header);

    await expect(approval).rejects.toThrow('oversized frame');
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('rejects an acknowledgement bound to a different approval digest', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestIdFactory: () => 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approval = runtime.authorizeTask(validApproval(path.resolve(binDirectory)));
    fake.stdout.write(
      controlFrame({
        schema_version: 2,
        request_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        status: 'ACK',
        code: 'SESSION_APPROVED',
        approval_digest: `sha256:${'c'.repeat(64)}`,
      })
    );

    await expect(approval).rejects.toThrow('digest does not match');
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });

  it('rejects an in-flight approval when the private output pipe is lost', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    const approval = runtime.authorizeTask(validApproval(path.resolve(binDirectory)));
    fake.stdout.end();

    await expect(approval).rejects.toThrow('control output closed');
    await runtime.cleanup();
  });

  it('makes an ambiguous timeout terminal and refuses invalid local authority', async () => {
    const fake = createFakeRuntimeProcess();
    const binDirectory = createRuntimeBundle();
    const runtimePromise = startAccordLockRuntime({
      binDirectory,
      dataDirectory: makeTempDirectory(),
      logger: { info: () => {}, error: () => {} },
      readinessFetch: successfulHealth,
      spawnProcess: () => fake.child,
      tokenFactory: () => 'A'.repeat(43),
      controlRequestTimeoutMs: 10,
    });
    fake.stdout.write(readyLine);
    const runtime = await runtimePromise;
    await expect(
      runtime.authorizeTask({ ...validApproval(path.resolve(binDirectory)), policy_epoch: 0 })
    ).rejects.toThrow('strict control profile');
    await expect(
      runtime.revokeSession({ ...validRevocation(), run_id: ' non-canonical' })
    ).rejects.toThrow('strict control profile');
    const approvedSession = validApproval(path.resolve(binDirectory));
    await expect(
      runtime.authorizeTask({
        ...approvedSession,
        task_policy_hash: `sha256:${'f'.repeat(64)}`,
      })
    ).rejects.toThrow('hash does not match');
    await expect(
      runtime.authorizeTask({
        ...approvedSession,
        task_objective: 'A substituted objective.',
      })
    ).rejects.toThrow('task objective does not match');
    await expect(
      runtime.authorizeTask({
        ...approvedSession,
        task_policy: {
          ...approvedSession.task_policy,
          preauthorized_capabilities: [{ extension_id: 'developer', tool_name: 'write' }],
        },
      })
    ).rejects.toThrow('native safe profile');
    const actionApproval = validActionApproval(approvedSession.task_policy_hash);
    await expect(
      runtime.registerActionApproval({ ...actionApproval, expires_at: 411 })
    ).rejects.toThrow('strict control profile');
    await expect(
      runtime.registerActionApproval({
        ...actionApproval,
        policy_decision_hash: `sha256:${'0'.repeat(64)}`,
      })
    ).rejects.toThrow('strict control profile');
    await expect(
      runtime.registerActionApproval({ ...actionApproval, policy_decision: null as never })
    ).rejects.toThrow('strict control profile');

    await expect(runtime.authorizeTask(approvedSession)).rejects.toThrow('timed out');
    expect(fake.killedSignals).toContain('SIGTERM');
    await runtime.cleanup();
  });
});
