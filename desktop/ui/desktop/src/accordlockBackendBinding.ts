import { createHmac, randomBytes } from 'node:crypto';

export const ACCORDLOCK_BACKEND_BINDING_SECRET_ENV = 'ACCORDLOCK_BACKEND_BINDING_SECRET';
export const ACCORDLOCK_BACKEND_BINDING_DOMAIN = 'accordlock.backend-run/v1';

const BACKEND_BINDING_SECRET_BYTES = 32;
const BACKEND_BINDING_SECRET_LENGTH = 43;
const MAX_SESSION_ID_BYTES = 512;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]{43}$/;
const CONTROL_CHARACTER = /\p{Cc}/u;

const decodeBackendBindingSecret = (secret: string): Buffer => {
  if (secret.length !== BACKEND_BINDING_SECRET_LENGTH || !CANONICAL_BASE64URL.test(secret)) {
    throw new Error('AccordLock backend binding secret is invalid');
  }

  const decoded = Buffer.from(secret, 'base64url');
  if (decoded.length !== BACKEND_BINDING_SECRET_BYTES || decoded.toString('base64url') !== secret) {
    throw new Error('AccordLock backend binding secret is invalid');
  }
  return decoded;
};

const encodeBackendBindingMessage = (sessionId: string): Buffer => {
  const sessionBytes = Buffer.from(sessionId, 'utf8');
  if (
    sessionBytes.length === 0 ||
    sessionBytes.length > MAX_SESSION_ID_BYTES ||
    CONTROL_CHARACTER.test(sessionId)
  ) {
    throw new Error('AccordLock session identifier is invalid');
  }

  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(sessionBytes.length);
  return Buffer.concat([
    Buffer.from(ACCORDLOCK_BACKEND_BINDING_DOMAIN, 'ascii'),
    Buffer.from([0]),
    length,
    sessionBytes,
  ]);
};

export const assertAccordLockBackendBindingSecret = (secret: string): void => {
  decodeBackendBindingSecret(secret);
};

export const generateAccordLockBackendBindingSecret = (): string =>
  randomBytes(BACKEND_BINDING_SECRET_BYTES).toString('base64url');

export const deriveAccordLockBackendRunId = (secret: string, sessionId: string): string => {
  const key = decodeBackendBindingSecret(secret);
  const message = encodeBackendBindingMessage(sessionId);
  return `sha256:${createHmac('sha256', key).update(message).digest('hex')}`;
};
