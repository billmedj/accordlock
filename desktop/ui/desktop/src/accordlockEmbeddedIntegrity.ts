declare const __ACCORDLOCK_GOOSE_BINARY_SHA256__: string;
declare const __ACCORDLOCK_RUNTIME_BINARY_SHA256__: string;
declare const __ACCORDLOCK_PREFLIGHT_BINARY_SHA256__: string;
declare const __ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__: number;
declare const __ACCORDLOCK_DEVELOPMENT_PACKAGE__: boolean;

function embeddedDigest(value: unknown): string | undefined {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value) ? value : undefined;
}

export function embeddedGooseBinarySha256(): string | undefined {
  return embeddedDigest(
    typeof __ACCORDLOCK_GOOSE_BINARY_SHA256__ === 'string'
      ? __ACCORDLOCK_GOOSE_BINARY_SHA256__
      : undefined
  );
}

export function embeddedRuntimeBinarySha256(): string | undefined {
  return embeddedDigest(
    typeof __ACCORDLOCK_RUNTIME_BINARY_SHA256__ === 'string'
      ? __ACCORDLOCK_RUNTIME_BINARY_SHA256__
      : undefined
  );
}

export function embeddedPreflightBinarySha256(): string | undefined {
  const value =
    typeof __ACCORDLOCK_PREFLIGHT_BINARY_SHA256__ === 'string'
      ? __ACCORDLOCK_PREFLIGHT_BINARY_SHA256__
      : undefined;
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value) ? value : undefined;
}

export function embeddedPreflightProtocolVersion(): number | undefined {
  return typeof __ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__ === 'number' &&
    Number.isSafeInteger(__ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__) &&
    __ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__ > 0
    ? __ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__
    : undefined;
}

export function isEmbeddedAccordLockDevelopmentPackage(): boolean {
  return (
    typeof __ACCORDLOCK_DEVELOPMENT_PACKAGE__ === 'boolean' && __ACCORDLOCK_DEVELOPMENT_PACKAGE__
  );
}
