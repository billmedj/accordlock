import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import type { AddressInfo } from 'node:net';

export const ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES = 320 * 1024;
export const ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES = 8 * 1024 * 1024;
export const ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES = 384 * 1024;

export type AccordLockRuntimePath =
  | '/api/v2/health'
  | '/api/v2/execution/filesystem/authorize-and-execute'
  | '/api/v2/execution/terminal/authorize-and-execute'
  | '/api/v2/execution/network/authorize-and-execute';

export type AccordLockRuntimeMethod = 'GET' | 'POST';

export interface AccordLockApprovalProxyResponse {
  status: number;
  contentType: string | null;
  body: Uint8Array;
}

export interface AccordLockApprovalRequest {
  path: AccordLockRuntimePath;
  requestBody: Uint8Array;
  responseBody: Uint8Array;
}

export interface AccordLockApprovalProxyOptions {
  forward: (
    path: AccordLockRuntimePath,
    method: AccordLockRuntimeMethod,
    body: Uint8Array
  ) => Promise<AccordLockApprovalProxyResponse>;
  resolveApproval: (request: AccordLockApprovalRequest) => Promise<boolean>;
}

export interface AccordLockApprovalProxyHandle {
  baseUrl: string;
  bearer: string;
  cleanup: () => Promise<void>;
}

const RUNTIME_ROUTES = new Map<AccordLockRuntimePath, AccordLockRuntimeMethod>([
  ['/api/v2/health', 'GET'],
  ['/api/v2/execution/filesystem/authorize-and-execute', 'POST'],
  ['/api/v2/execution/terminal/authorize-and-execute', 'POST'],
  ['/api/v2/execution/network/authorize-and-execute', 'POST'],
]);

export function accordLockApprovalProxyRequestLimit(_path: AccordLockRuntimePath): number {
  return ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES;
}

export function accordLockApprovalProxyResponseLimit(path: AccordLockRuntimePath): number {
  if (path === '/api/v2/execution/terminal/authorize-and-execute') {
    return ACCORDLOCK_APPROVAL_PROXY_MAX_TERMINAL_RESPONSE_BYTES;
  }
  if (path === '/api/v2/execution/network/authorize-and-execute') {
    return ACCORDLOCK_APPROVAL_PROXY_MAX_NETWORK_RESPONSE_BYTES;
  }
  return ACCORDLOCK_APPROVAL_PROXY_MAX_BODY_BYTES;
}

const ERROR_BODY = Buffer.from('{"error":"REQUEST_REJECTED"}', 'utf8');
const JSON_CONTENT_TYPE = 'application/json';

class BodyTooLargeError extends Error {}

class InvalidBodyError extends Error {}

function rawHeaderValues(request: IncomingMessage, target: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === target) {
      values.push(request.rawHeaders[index + 1] ?? '');
    }
  }
  return values;
}

function bearerDigest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function hasExactBearer(request: IncomingMessage, bearer: string): boolean {
  const values = rawHeaderValues(request, 'authorization');
  if (values.length !== 1 || !values[0]?.startsWith('Bearer ')) return false;
  return timingSafeEqual(bearerDigest(values[0].slice('Bearer '.length)), bearerDigest(bearer));
}

function hasExactJsonContentType(request: IncomingMessage): boolean {
  const values = rawHeaderValues(request, 'content-type');
  return values.length === 1 && values[0]?.toLowerCase() === JSON_CONTENT_TYPE;
}

function hasNoContentType(request: IncomingMessage): boolean {
  return rawHeaderValues(request, 'content-type').length === 0;
}

function declaredContentLength(request: IncomingMessage, maximumBytes: number): number | null {
  const values = rawHeaderValues(request, 'content-length');
  if (values.length === 0) return null;
  if (values.length !== 1 || !/^(0|[1-9][0-9]*)$/u.test(values[0] ?? '')) {
    throw new InvalidBodyError();
  }
  const length = Number(values[0]);
  if (!Number.isSafeInteger(length)) throw new InvalidBodyError();
  if (length > maximumBytes) throw new BodyTooLargeError();
  return length;
}

function readBoundedBody(request: IncomingMessage, maximumBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let expectedLength: number | null;
    try {
      expectedLength = declaredContentLength(request, maximumBytes);
    } catch (error) {
      request.resume();
      reject(error);
      return;
    }

    const chunks: Buffer[] = [];
    let length = 0;
    let settled = false;

    const rejectOnce = (error: Error) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      request.resume();
      reject(error);
    };

    request.on('data', (chunk: Buffer | string) => {
      if (settled) return;
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      length += bytes.length;
      if (length > maximumBytes) {
        rejectOnce(new BodyTooLargeError());
        return;
      }
      chunks.push(Buffer.from(bytes));
    });
    request.once('aborted', () => rejectOnce(new InvalidBodyError()));
    request.once('error', () => rejectOnce(new InvalidBodyError()));
    request.once('end', () => {
      if (settled) return;
      if (expectedLength !== null && expectedLength !== length) {
        rejectOnce(new InvalidBodyError());
        return;
      }
      settled = true;
      resolve(Buffer.concat(chunks, length));
    });
  });
}

function sendError(response: ServerResponse, status: number): void {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Length': ERROR_BODY.length,
    'Content-Type': JSON_CONTENT_TYPE,
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(ERROR_BODY);
}

function normalizeForwardedResponse(
  value: AccordLockApprovalProxyResponse,
  maximumBytes: number
): {
  status: number;
  contentType: string | null;
  body: Buffer;
} {
  if (
    typeof value !== 'object' ||
    value === null ||
    !Number.isInteger(value.status) ||
    value.status < 200 ||
    value.status > 599 ||
    (value.contentType !== null &&
      (typeof value.contentType !== 'string' ||
        value.contentType.length === 0 ||
        value.contentType.length > 256 ||
        /[\r\n]/u.test(value.contentType))) ||
    !(
      Buffer.isBuffer(value.body) ||
      (ArrayBuffer.isView(value.body) &&
        Object.prototype.toString.call(value.body) === '[object Uint8Array]')
    )
  ) {
    throw new Error('Invalid forwarded response');
  }
  const body = Buffer.from(value.body);
  if (body.length > maximumBytes) {
    throw new Error('Forwarded response is too large');
  }
  return { status: value.status, contentType: value.contentType, body };
}

function sendForwardedResponse(
  response: ServerResponse,
  forwarded: ReturnType<typeof normalizeForwardedResponse>
): void {
  const headers: Record<string, string | number> = {
    'Cache-Control': 'no-store',
    'Content-Length': forwarded.body.length,
    'X-Content-Type-Options': 'nosniff',
  };
  if (forwarded.contentType !== null) headers['Content-Type'] = forwarded.contentType;
  response.writeHead(forwarded.status, headers);
  response.end(forwarded.body);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface ApprovalMarker {
  proposalDigest: string | null;
  approvalId: string | null;
  approvalRequestHash: string | null;
}

function boundedIdentity(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 ? value : null;
}

function approvalMarker(body: Buffer): ApprovalMarker | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    if (
      !isRecord(value) ||
      (value.status !== 'APPROVAL_REQUIRED' && value.decision !== 'APPROVAL_REQUIRED')
    ) {
      return null;
    }
    return {
      proposalDigest: boundedIdentity(value.proposal_digest),
      approvalId: boundedIdentity(value.approval_id),
      approvalRequestHash: boundedIdentity(value.approval_request_hash),
    };
  } catch {
    return null;
  }
}

function approvalFlightKey(
  path: AccordLockRuntimePath,
  requestBody: Buffer,
  marker: ApprovalMarker
): string {
  const requestDigest = createHash('sha256').update(requestBody).digest('hex');
  return JSON.stringify([
    path,
    requestDigest,
    marker.proposalDigest,
    marker.approvalId,
    marker.approvalRequestHash,
  ]);
}

class ApprovalResolutionSingleFlight {
  private readonly resolutions = new Map<string, Promise<boolean>>();

  resolve(key: string, operation: () => Promise<boolean>): Promise<boolean> {
    const existing = this.resolutions.get(key);
    if (existing !== undefined) return existing;

    const resolution = Promise.resolve().then(operation);
    this.resolutions.set(key, resolution);
    const remove = () => {
      if (this.resolutions.get(key) === resolution) this.resolutions.delete(key);
    };
    void resolution.then(remove, remove);
    return resolution;
  }
}

export function isAccordLockApprovalProxyLoopbackAddress(address: string | undefined): boolean {
  if (address === undefined) return false;
  const normalized = address.toLowerCase();
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  const mapped = normalized.startsWith('::ffff:') ? normalized.slice('::ffff:'.length) : normalized;
  return isIP(mapped) === 4 && mapped.split('.')[0] === '127';
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  bearer: string,
  options: AccordLockApprovalProxyOptions,
  approvalResolutions: ApprovalResolutionSingleFlight
): Promise<void> {
  if (!isAccordLockApprovalProxyLoopbackAddress(request.socket.remoteAddress)) {
    sendError(response, 403);
    return;
  }
  if (!hasExactBearer(request, bearer)) {
    response.setHeader('WWW-Authenticate', 'Bearer realm="accordlock-approval-proxy"');
    sendError(response, 401);
    return;
  }

  const path = request.url as AccordLockRuntimePath | undefined;
  const expectedMethod = path === undefined ? undefined : RUNTIME_ROUTES.get(path);
  if (path === undefined || expectedMethod === undefined) {
    sendError(response, 404);
    return;
  }
  if (request.method !== expectedMethod) {
    sendError(response, 405);
    return;
  }
  if (
    (expectedMethod === 'POST' && !hasExactJsonContentType(request)) ||
    (expectedMethod === 'GET' && !hasNoContentType(request))
  ) {
    sendError(response, 415);
    return;
  }

  let requestBody: Buffer;
  try {
    requestBody = await readBoundedBody(request, accordLockApprovalProxyRequestLimit(path));
  } catch (error) {
    sendError(response, error instanceof BodyTooLargeError ? 413 : 400);
    return;
  }
  if (expectedMethod === 'GET' && requestBody.length !== 0) {
    sendError(response, 400);
    return;
  }

  try {
    const first = normalizeForwardedResponse(
      await options.forward(path, expectedMethod, Buffer.from(requestBody)),
      accordLockApprovalProxyResponseLimit(path)
    );
    const marker = approvalMarker(first.body);
    if (marker === null) {
      sendForwardedResponse(response, first);
      return;
    }

    const approved = await approvalResolutions.resolve(
      approvalFlightKey(path, requestBody, marker),
      () =>
        options.resolveApproval({
          path,
          requestBody: Buffer.from(requestBody),
          responseBody: Buffer.from(first.body),
        })
    );
    if (typeof approved !== 'boolean') throw new Error('Invalid approval resolution');
    if (!approved) {
      sendForwardedResponse(response, first);
      return;
    }

    const retried = normalizeForwardedResponse(
      await options.forward(path, expectedMethod, Buffer.from(requestBody)),
      accordLockApprovalProxyResponseLimit(path)
    );
    sendForwardedResponse(response, retried);
  } catch {
    sendError(response, 503);
  }
}

export async function startAccordLockApprovalProxy(
  options: AccordLockApprovalProxyOptions
): Promise<AccordLockApprovalProxyHandle> {
  if (typeof options?.forward !== 'function' || typeof options.resolveApproval !== 'function') {
    throw new TypeError('AccordLock approval proxy callbacks are required');
  }

  const bearer = randomBytes(32).toString('base64url');
  const approvalResolutions = new ApprovalResolutionSingleFlight();
  const server = createServer(
    {
      headersTimeout: 10_000,
      keepAliveTimeout: 1_000,
      maxHeaderSize: 16 * 1024,
      requestTimeout: 10_000,
    },
    (request, response) => {
      void handleRequest(request, response, bearer, options, approvalResolutions).catch(() => {
        if (!response.headersSent) sendError(response, 503);
        else response.destroy();
      });
    }
  );

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(0, '127.0.0.1');
  });

  const address = server.address() as AddressInfo | null;
  if (address === null || address.address !== '127.0.0.1') {
    server.close();
    throw new Error('AccordLock approval proxy did not bind the IPv4 loopback');
  }

  let cleanupPromise: Promise<void> | null = null;
  const cleanup = (): Promise<void> => {
    if (cleanupPromise !== null) return cleanupPromise;
    cleanupPromise = new Promise((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close((error) => {
        const code = error !== undefined && 'code' in error ? error.code : undefined;
        if (error && code !== 'ERR_SERVER_NOT_RUNNING') {
          reject(error);
        } else {
          resolve();
        }
      });
      server.closeIdleConnections();
      server.closeAllConnections();
    });
    return cleanupPromise;
  };

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    bearer,
    cleanup,
  };
}
