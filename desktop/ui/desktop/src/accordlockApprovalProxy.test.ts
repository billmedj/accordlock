import { request } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES,
  ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES,
  ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES,
  isAccordLockApprovalProxyLoopbackAddress,
  startAccordLockApprovalProxy,
  type AccordLockApprovalProxyHandle,
  type AccordLockApprovalProxyOptions,
  type AccordLockApprovalProxyResponse,
} from './accordlockApprovalProxy';

interface ProxyRequest {
  path?: string;
  method?: string;
  bearer?: string | null;
  contentType?: string | null;
  body?: Uint8Array;
  rawHeaders?: string[];
  signal?: AbortSignal;
}

interface ProxyResult {
  status: number;
  contentType: string | undefined;
  body: Buffer;
}

const handles: AccordLockApprovalProxyHandle[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.cleanup()));
  vi.restoreAllMocks();
});

function runtimeResponse(
  body: string | Uint8Array,
  status = 200,
  contentType: string | null = 'application/json'
): AccordLockApprovalProxyResponse {
  return {
    status,
    contentType,
    body: typeof body === 'string' ? Buffer.from(body, 'utf8') : body,
  };
}

async function start(overrides: Partial<AccordLockApprovalProxyOptions> = {}) {
  const options: AccordLockApprovalProxyOptions = {
    forward: vi.fn(async () => runtimeResponse('{"status":"OK"}')),
    resolveApproval: vi.fn(async () => false),
    ...overrides,
  };
  const handle = await startAccordLockApprovalProxy(options);
  handles.push(handle);
  return { handle, options };
}

function callProxy(
  handle: AccordLockApprovalProxyHandle,
  input: ProxyRequest = {}
): Promise<ProxyResult> {
  const target = new URL(handle.baseUrl);
  const body = Buffer.from(input.body ?? Buffer.alloc(0));
  let headers = input.rawHeaders ?? [
    ...(input.bearer === null ? [] : ['Authorization', `Bearer ${input.bearer ?? handle.bearer}`]),
    ...(input.contentType === null
      ? []
      : ['Content-Type', input.contentType ?? 'application/json']),
    'Content-Length',
    String(body.length),
  ];
  if (!headers.some((value, index) => index % 2 === 0 && value.toLowerCase() === 'host')) {
    headers = ['Host', target.host, ...headers];
  }
  return new Promise((resolve, reject) => {
    const outgoing = request(
      {
        host: target.hostname,
        port: target.port,
        path: input.path ?? '/api/v2/execution/filesystem/authorize-and-execute',
        method: input.method ?? 'POST',
        headers,
        signal: input.signal,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.once('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            contentType:
              typeof response.headers['content-type'] === 'string'
                ? response.headers['content-type']
                : undefined,
            body: Buffer.concat(chunks),
          });
        });
      }
    );
    outgoing.once('error', reject);
    outgoing.end(body);
  });
}

describe('AccordLock approval proxy', () => {
  it('uses a fresh 256-bit bearer and binds only the IPv4 loopback', async () => {
    const first = await start();
    const second = await start();

    expect(new URL(first.handle.baseUrl).hostname).toBe('127.0.0.1');
    expect(Buffer.from(first.handle.bearer, 'base64url')).toHaveLength(32);
    expect(Buffer.from(second.handle.bearer, 'base64url')).toHaveLength(32);
    expect(first.handle.bearer).not.toBe(second.handle.bearer);
  });

  it('recognizes only actual loopback address forms', () => {
    for (const address of [
      '127.0.0.1',
      '127.34.56.78',
      '::ffff:127.0.0.1',
      '::1',
      '0:0:0:0:0:0:0:1',
    ]) {
      expect(isAccordLockApprovalProxyLoopbackAddress(address)).toBe(true);
    }
    for (const address of [undefined, '', '0.0.0.0', '10.0.0.1', '::2', '127.example.com']) {
      expect(isAccordLockApprovalProxyLoopbackAddress(address)).toBe(false);
    }
  });

  it('forwards each exact runtime route with its exact method and request bytes', async () => {
    const forward = vi.fn(
      async (
        _path: Parameters<AccordLockApprovalProxyOptions['forward']>[0],
        _method: Parameters<AccordLockApprovalProxyOptions['forward']>[1],
        _body: Parameters<AccordLockApprovalProxyOptions['forward']>[2]
      ) => runtimeResponse('{"status":"OK"}')
    );
    const { handle } = await start({ forward });
    const postBody = Buffer.from([0, 1, 2, 255]);
    const routes = [
      ['/api/v2/health', 'GET', Buffer.alloc(0)],
      ['/api/v2/execution/filesystem/authorize-and-execute', 'POST', postBody],
      ['/api/v2/execution/terminal/authorize-and-execute', 'POST', postBody],
      ['/api/v2/execution/network/authorize-and-execute', 'POST', postBody],
    ] as const;

    for (const [path, method, body] of routes) {
      const result = await callProxy(handle, {
        path,
        method,
        body,
        contentType: method === 'GET' ? null : 'application/json',
      });
      expect(result.status, path).toBe(200);
    }

    expect(forward).toHaveBeenCalledTimes(4);
    routes.forEach(([path, method, body], index) => {
      const call = forward.mock.calls[index];
      expect(call?.[0]).toBe(path);
      expect(call?.[1]).toBe(method);
      expect(Buffer.from(call?.[2] ?? [])).toEqual(body);
    });
  });

  it.each([
    [
      'caller-reported authorization',
      '/api/v2/authorization/tool-calls/authorize-and-consume',
      '{"schema_version":2,"tool_name":"read"}',
    ],
    [
      'forged successful execution observation',
      '/api/v2/execution/tool-observations/record',
      JSON.stringify({
        schema_version: 2,
        authorization_id: '11111111-1111-4111-8111-111111111111',
        proposal_digest: `sha256:${'1'.repeat(64)}`,
        request_hash: `sha256:${'2'.repeat(64)}`,
        outcome: 'SUCCEEDED',
        result_digest: `sha256:${'3'.repeat(64)}`,
      }),
    ],
  ])('never exposes %s to Goose', async (_, path, body) => {
    const { handle, options } = await start();

    const result = await callProxy(handle, {
      path,
      body: Buffer.from(body, 'utf8'),
    });

    expect(result.status).toBe(404);
    expect(options.forward).not.toHaveBeenCalled();
    expect(options.resolveApproval).not.toHaveBeenCalled();
  });

  it('preserves upstream status, content type, and response bytes exactly', async () => {
    const bytes = Buffer.from([0, 255, 1, 128, 2]);
    const { handle } = await start({
      forward: vi.fn(async () => runtimeResponse(bytes, 418, 'application/octet-stream')),
    });

    const result = await callProxy(handle, { body: Buffer.from('{}') });

    expect(result.status).toBe(418);
    expect(result.contentType).toBe('application/octet-stream');
    expect(result.body).toEqual(bytes);
  });

  it.each([
    ['status', '{"status":"APPROVAL_REQUIRED","reason_code":"POLICY"}'],
    ['decision', '{"decision":"APPROVAL_REQUIRED","reason_code":"POLICY"}'],
  ])(
    'resolves a top-level %s approval and retries the identical request exactly once',
    async (_, json) => {
      const requestBody = Buffer.from('{"proposal":"exact"}');
      const firstBody = Buffer.from(json);
      const secondBody = Buffer.from('{"status":"SUCCEEDED"}');
      const forward = vi
        .fn()
        .mockResolvedValueOnce(runtimeResponse(firstBody, 409))
        .mockResolvedValueOnce(runtimeResponse(secondBody, 201));
      const resolveApproval = vi.fn(async (approval) => {
        expect(approval.path).toBe('/api/v2/execution/filesystem/authorize-and-execute');
        expect(Buffer.from(approval.requestBody)).toEqual(requestBody);
        expect(Buffer.from(approval.responseBody)).toEqual(firstBody);
        approval.requestBody[0] = 0;
        approval.responseBody[0] = 0;
        return true;
      });
      const { handle } = await start({ forward, resolveApproval });

      const result = await callProxy(handle, { body: requestBody });

      expect(result.status).toBe(201);
      expect(result.body).toEqual(secondBody);
      expect(resolveApproval).toHaveBeenCalledOnce();
      expect(forward).toHaveBeenCalledTimes(2);
      expect(forward.mock.calls[0]?.[0]).toBe(forward.mock.calls[1]?.[0]);
      expect(forward.mock.calls[0]?.[1]).toBe(forward.mock.calls[1]?.[1]);
      expect(Buffer.from(forward.mock.calls[0]?.[2] ?? [])).toEqual(requestBody);
      expect(Buffer.from(forward.mock.calls[1]?.[2] ?? [])).toEqual(requestBody);
    }
  );

  it('returns the original approval response without retry when approval is denied', async () => {
    const original = runtimeResponse('{"status":"APPROVAL_REQUIRED"}', 409);
    const forward = vi.fn(async () => original);
    const resolveApproval = vi.fn(async () => false);
    const { handle } = await start({ forward, resolveApproval });

    const result = await callProxy(handle, { body: Buffer.from('{}') });

    expect(result.status).toBe(original.status);
    expect(result.body).toEqual(Buffer.from(original.body));
    expect(forward).toHaveBeenCalledOnce();
    expect(resolveApproval).toHaveBeenCalledOnce();
  });

  it('never resolves or retries a second APPROVAL_REQUIRED response', async () => {
    const approval = runtimeResponse('{"decision":"APPROVAL_REQUIRED"}', 409);
    const forward = vi.fn(async () => approval);
    const resolveApproval = vi.fn(async () => true);
    const { handle } = await start({ forward, resolveApproval });

    const result = await callProxy(handle, { body: Buffer.from('{}') });

    expect(result.status).toBe(409);
    expect(forward).toHaveBeenCalledTimes(2);
    expect(resolveApproval).toHaveBeenCalledOnce();
  });

  it('shares one pending decision for concurrent requests with the same fingerprint', async () => {
    let releaseApproval: ((approved: boolean) => void) | undefined;
    const approvalDecision = new Promise<boolean>((resolve) => {
      releaseApproval = resolve;
    });
    const approval = runtimeResponse(
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_id":"approval-same"}',
      409
    );
    const forward = vi
      .fn()
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(runtimeResponse('{"status":"SUCCEEDED"}', 200))
      .mockResolvedValueOnce(runtimeResponse('{"status":"DENIED"}', 409));
    const resolveApproval = vi.fn(() => approvalDecision);
    const { handle } = await start({ forward, resolveApproval });
    const body = Buffer.from('{"proposal":"same"}');

    const first = callProxy(handle, { body });
    const second = callProxy(handle, { body });
    await vi.waitFor(() => {
      expect(forward).toHaveBeenCalledTimes(2);
      expect(resolveApproval).toHaveBeenCalledOnce();
    });
    releaseApproval?.(true);
    const results = await Promise.all([first, second]);

    expect(results.map((result) => result.status).sort()).toEqual([200, 409]);
    expect(resolveApproval).toHaveBeenCalledOnce();
    expect(forward).toHaveBeenCalledTimes(4);
  });

  it('cancels a pending resolution and never retries after the client disconnects', async () => {
    const approval = runtimeResponse(
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:cancelled"}',
      409
    );
    const forward = vi.fn(async () => approval);
    let resolutionSignal: AbortSignal | undefined;
    const resolveApproval = vi.fn(
      ({ signal }: { signal: AbortSignal }) =>
        new Promise<boolean>((resolve) => {
          resolutionSignal = signal;
          signal.addEventListener('abort', () => resolve(false), { once: true });
        })
    );
    const { handle } = await start({ forward, resolveApproval });
    const client = new AbortController();

    const pending = callProxy(handle, {
      body: Buffer.from('{"proposal":"cancelled"}'),
      signal: client.signal,
    });
    await vi.waitFor(() => expect(resolveApproval).toHaveBeenCalledOnce());
    client.abort();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    await vi.waitFor(() => expect(resolutionSignal?.aborted).toBe(true));
    expect(forward).toHaveBeenCalledOnce();
  });

  it('keeps a shared approval alive while another identical client is connected', async () => {
    const approval = runtimeResponse(
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:shared-cancel"}',
      409
    );
    const forward = vi
      .fn()
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(approval)
      .mockResolvedValueOnce(runtimeResponse('{"status":"SUCCEEDED"}', 200));
    let releaseApproval: ((approved: boolean) => void) | undefined;
    let resolutionSignal: AbortSignal | undefined;
    const resolveApproval = vi.fn(
      ({ signal }: { signal: AbortSignal }) =>
        new Promise<boolean>((resolve) => {
          resolutionSignal = signal;
          releaseApproval = resolve;
        })
    );
    const { handle } = await start({ forward, resolveApproval });
    const firstClient = new AbortController();
    const body = Buffer.from('{"proposal":"shared-cancel"}');

    const first = callProxy(handle, { body, signal: firstClient.signal });
    const second = callProxy(handle, { body });
    await vi.waitFor(() => {
      expect(forward).toHaveBeenCalledTimes(2);
      expect(resolveApproval).toHaveBeenCalledOnce();
    });
    firstClient.abort();

    await expect(first).rejects.toMatchObject({ name: 'AbortError' });
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
    expect(resolutionSignal?.aborted).toBe(false);
    expect(forward).toHaveBeenCalledTimes(2);
    releaseApproval?.(true);
    await expect(second).resolves.toMatchObject({ status: 200 });
    expect(forward).toHaveBeenCalledTimes(3);
    expect(
      forward.mock.calls.map(([requestPath, method, requestBody]) => [
        requestPath,
        method,
        Buffer.from(requestBody),
      ])
    ).toEqual([
      ['/api/v2/execution/filesystem/authorize-and-execute', 'POST', body],
      ['/api/v2/execution/filesystem/authorize-and-execute', 'POST', body],
      ['/api/v2/execution/filesystem/authorize-and-execute', 'POST', body],
    ]);
  });

  it.each([
    [
      'execution request fingerprint',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:first","approval_id":"approval"}',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:second","approval_id":"approval"}',
    ],
    [
      'approval id',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_id":"first"}',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_id":"second"}',
    ],
    [
      'approval context hash',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_request_hash":"sha256:first"}',
      '{"status":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_request_hash":"sha256:second"}',
    ],
  ])('never merges concurrent approvals with a different %s', async (_, firstJson, secondJson) => {
    const forward = vi
      .fn()
      .mockResolvedValueOnce(runtimeResponse(firstJson, 409))
      .mockResolvedValueOnce(runtimeResponse(secondJson, 409));
    const decisions: Array<(approved: boolean) => void> = [];
    const resolveApproval = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          decisions.push(resolve);
        })
    );
    const { handle } = await start({ forward, resolveApproval });
    const body = Buffer.from('{"proposal":"same"}');

    const first = callProxy(handle, { body });
    const second = callProxy(handle, { body });
    await vi.waitFor(() => expect(resolveApproval).toHaveBeenCalledTimes(2));
    decisions.forEach((resolve) => resolve(false));
    await Promise.all([first, second]);

    expect(forward).toHaveBeenCalledTimes(2);
    expect(resolveApproval).toHaveBeenCalledTimes(2);
  });

  it('does not merge different request bytes even when response identifiers match', async () => {
    const approval = runtimeResponse(
      '{"decision":"APPROVAL_REQUIRED","proposal_digest":"sha256:same","approval_id":"same"}',
      409
    );
    const forward = vi.fn(async () => approval);
    const decisions: Array<(approved: boolean) => void> = [];
    const resolveApproval = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          decisions.push(resolve);
        })
    );
    const { handle } = await start({ forward, resolveApproval });

    const first = callProxy(handle, { body: Buffer.from('{"proposal":1}') });
    const second = callProxy(handle, { body: Buffer.from('{"proposal":2}') });
    await vi.waitFor(() => expect(resolveApproval).toHaveBeenCalledTimes(2));
    decisions.forEach((resolve) => resolve(false));
    await Promise.all([first, second]);

    expect(resolveApproval).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['reason code alone', '{"status":"DENIED","reason_code":"APPROVAL_REQUIRED"}'],
    ['nested marker', '{"result":{"status":"APPROVAL_REQUIRED"}}'],
    ['malformed JSON', '{"status":"APPROVAL_REQUIRED"'],
    ['unrelated response', '{"status":"DENIED"}'],
  ])('does not resolve %s', async (_, body) => {
    const forward = vi.fn(async () => runtimeResponse(body, 409));
    const resolveApproval = vi.fn(async () => true);
    const { handle } = await start({ forward, resolveApproval });

    await callProxy(handle, { body: Buffer.from('{}') });

    expect(forward).toHaveBeenCalledOnce();
    expect(resolveApproval).not.toHaveBeenCalled();
  });

  it.each([
    ['missing bearer', { bearer: null }],
    ['wrong bearer', { bearer: 'wrong' }],
    [
      'duplicate bearer',
      {
        rawHeaders: [
          'Authorization',
          'Bearer first',
          'Authorization',
          'Bearer second',
          'Content-Type',
          'application/json',
          'Content-Length',
          '2',
        ],
      },
    ],
  ])('rejects a %s before forwarding', async (_, input) => {
    const { handle, options } = await start();

    const result = await callProxy(handle, { body: Buffer.from('{}'), ...input });

    expect(result.status).toBe(401);
    expect(options.forward).not.toHaveBeenCalled();
    expect(options.resolveApproval).not.toHaveBeenCalled();
  });

  it.each([
    ['unknown route', { path: '/api/unsupported' }, 404],
    ['query-bearing route', { path: '/api/v2/health?probe=true', method: 'GET' }, 404],
    ['wrong POST route method', { method: 'GET', contentType: null }, 405],
    ['wrong health method', { path: '/api/v2/health', method: 'POST' }, 405],
  ])('rejects the %s', async (_, input, expectedStatus) => {
    const { handle, options } = await start();

    const result = await callProxy(handle, { body: Buffer.alloc(0), ...input });

    expect(result.status).toBe(expectedStatus);
    expect(options.forward).not.toHaveBeenCalled();
  });

  it.each([
    ['missing JSON content type', { contentType: null }],
    ['parameterized JSON content type', { contentType: 'application/json; charset=utf-8' }],
    ['wrong content type', { contentType: 'text/plain' }],
    [
      'duplicate content type',
      {
        rawHeaders: [
          'Authorization',
          'PLACEHOLDER',
          'Content-Type',
          'application/json',
          'Content-Type',
          'application/json',
          'Content-Length',
          '2',
        ],
      },
    ],
  ])('rejects a POST with %s', async (_, input) => {
    const { handle, options } = await start();
    if ('rawHeaders' in input) input.rawHeaders[1] = `Bearer ${handle.bearer}`;

    const result = await callProxy(handle, { body: Buffer.from('{}'), ...input });

    expect(result.status).toBe(415);
    expect(options.forward).not.toHaveBeenCalled();
  });

  it('rejects a content type or body on the GET health route', async () => {
    const { handle, options } = await start();

    const contentType = await callProxy(handle, {
      path: '/api/v2/health',
      method: 'GET',
      contentType: 'application/json',
    });
    const body = await callProxy(handle, {
      path: '/api/v2/health',
      method: 'GET',
      contentType: null,
      body: Buffer.from('x'),
    });

    expect(contentType.status).toBe(415);
    expect(body.status).toBe(400);
    expect(options.forward).not.toHaveBeenCalled();
  });

  it('accepts exactly 320 KiB and rejects the next byte without forwarding it', async () => {
    const forward = vi.fn(async () => runtimeResponse('{"status":"OK"}'));
    const { handle } = await start({ forward });

    const accepted = await callProxy(handle, {
      body: Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES, 1),
    });
    const rejected = await callProxy(handle, {
      body: Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES + 1, 1),
    });

    expect(accepted.status).toBe(200);
    expect(rejected.status).toBe(413);
    expect(forward).toHaveBeenCalledOnce();
  });

  it('keeps terminal requests at 320 KiB and rejects the next byte before forwarding', async () => {
    const forward = vi.fn(async () => runtimeResponse('{"status":"OK"}'));
    const { handle } = await start({ forward });
    const path = '/api/v2/execution/terminal/authorize-and-execute';

    const accepted = await callProxy(handle, {
      path,
      body: Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES, 1),
    });
    const rejected = await callProxy(handle, {
      path,
      body: Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES + 1, 1),
    });

    expect(accepted.status).toBe(200);
    expect(rejected.status).toBe(413);
    expect(forward).toHaveBeenCalledOnce();
  });

  it('accepts an exact 8 MiB terminal response and rejects the next byte', async () => {
    const path = '/api/v2/execution/terminal/authorize-and-execute';
    const accepted = await start({
      forward: vi.fn(async () =>
        runtimeResponse(
          Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES),
          200,
          'application/octet-stream'
        )
      ),
    });
    const rejected = await start({
      forward: vi.fn(async () =>
        runtimeResponse(
          Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES + 1),
          200,
          'application/octet-stream'
        )
      ),
    });

    const acceptedResult = await callProxy(accepted.handle, { path, body: Buffer.from('{}') });
    const rejectedResult = await callProxy(rejected.handle, { path, body: Buffer.from('{}') });

    expect(acceptedResult.status).toBe(200);
    expect(acceptedResult.body).toHaveLength(ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES);
    expect(rejectedResult.status).toBe(503);
  });

  it('bounds the controlled network response independently of terminal output', async () => {
    const path = '/api/v2/execution/network/authorize-and-execute';
    const accepted = await start({
      forward: vi.fn(async () =>
        runtimeResponse(Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES))
      ),
    });
    const rejected = await start({
      forward: vi.fn(async () =>
        runtimeResponse(Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES + 1))
      ),
    });

    const acceptedResult = await callProxy(accepted.handle, { path, body: Buffer.from('{}') });
    const rejectedResult = await callProxy(rejected.handle, { path, body: Buffer.from('{}') });

    expect(acceptedResult.status).toBe(200);
    expect(acceptedResult.body).toHaveLength(ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES);
    expect(rejectedResult.status).toBe(503);
  });

  it.each(['forward', 'approval', 'retry'] as const)(
    'fails closed when the trusted %s callback throws',
    async (failure) => {
      const approval = runtimeResponse('{"status":"APPROVAL_REQUIRED"}', 409);
      const forward = vi.fn(async () => runtimeResponse('{"status":"OK"}'));
      const resolveApproval = vi.fn(async () => true);
      if (failure === 'forward') forward.mockRejectedValueOnce(new Error('no runtime'));
      if (failure === 'approval') {
        forward.mockResolvedValueOnce(approval);
        resolveApproval.mockRejectedValueOnce(new Error('no decision'));
      }
      if (failure === 'retry') {
        forward
          .mockResolvedValueOnce(approval)
          .mockRejectedValueOnce(new Error('retry unavailable'));
      }
      const { handle } = await start({ forward, resolveApproval });

      const result = await callProxy(handle, { body: Buffer.from('{}') });

      expect(result.status).toBe(503);
      expect(result.body.toString('utf8')).toBe('{"error":"REQUEST_REJECTED"}');
    }
  );

  it('fails closed on malformed or oversized forwarded responses', async () => {
    const malformed = await start({
      forward: vi.fn(async () => ({
        status: 99,
        contentType: 'application/json',
        body: Buffer.from('{}'),
      })),
    });
    const oversized = await start({
      forward: vi.fn(async () =>
        runtimeResponse(Buffer.alloc(ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES + 1))
      ),
    });

    const malformedResult = await callProxy(malformed.handle, { body: Buffer.from('{}') });
    const oversizedResult = await callProxy(oversized.handle, { body: Buffer.from('{}') });

    expect(malformedResult.status).toBe(503);
    expect(oversizedResult.status).toBe(503);
  });

  it('cleans up idempotently and stops accepting connections', async () => {
    const { handle } = await start();

    const first = handle.cleanup();
    const second = handle.cleanup();
    expect(second).toBe(first);
    await first;

    await expect(callProxy(handle, { body: Buffer.from('{}') })).rejects.toBeDefined();
  });

  it('cleans up promptly while an approval resolution is still pending', async () => {
    const approval = runtimeResponse('{"status":"APPROVAL_REQUIRED"}', 409);
    const resolveApproval = vi.fn(() => new Promise<boolean>(() => undefined));
    const { handle } = await start({
      forward: vi.fn(async () => approval),
      resolveApproval,
    });

    const pendingRequest = callProxy(handle, { body: Buffer.from('{}') });
    await vi.waitFor(() => expect(resolveApproval).toHaveBeenCalledOnce());

    await expect(handle.cleanup()).resolves.toBeUndefined();
    await expect(pendingRequest).rejects.toBeDefined();
  });
});
