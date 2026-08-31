export function shouldEnableAccordLockRemoteDebugging(
  isPackaged: boolean,
  explicitTestFlag: string | undefined
): boolean {
  return !isPackaged && explicitTestFlag === '1';
}

export function isAccordLockUnsafeViewMenuRole(role: string | undefined): boolean {
  const normalized = role?.toLowerCase();
  return normalized === 'reload' || normalized === 'forcereload' || normalized === 'toggledevtools';
}

export function isAccordLockExternalUrlAllowed(rawUrl: string): boolean {
  try {
    const protocol = new URL(rawUrl).protocol;
    return protocol === 'https:' || protocol === 'mailto:';
  } catch {
    return false;
  }
}

export class AccordLockNavigationAllowance {
  private readonly expectedUrlByWindow = new Map<number, string>();

  arm(windowId: number, exactUrl: string): void {
    if (!exactUrl) throw new Error('Cannot authorize an empty navigation target');
    this.expectedUrlByWindow.set(windowId, exactUrl);
  }

  consume(windowId: number, exactUrl: string): boolean {
    const expected = this.expectedUrlByWindow.get(windowId);
    if (expected === undefined) return false;
    this.expectedUrlByWindow.delete(windowId);
    return expected === exactUrl;
  }

  clear(windowId: number): void {
    this.expectedUrlByWindow.delete(windowId);
  }
}

export function shouldAllowAccordLockExternalBackend(
  isPackaged: boolean,
  explicitDevelopmentFlag: string | undefined
): boolean {
  return !isPackaged && explicitDevelopmentFlag === '1';
}

interface AccordLockMediaPermissionContext {
  permission: string;
  currentUrl: string;
  requestingUrl?: string;
  securityOrigin?: string;
  isMainFrame?: boolean;
}

interface AccordLockMediaPermissionCheck extends AccordLockMediaPermissionContext {
  requestingOrigin: string;
  mediaType?: string;
}

interface AccordLockMediaPermissionRequest extends AccordLockMediaPermissionContext {
  mediaTypes?: readonly string[];
}

function parseUrl(value: string | undefined): URL | null {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isSameRendererDocument(currentUrl: string, candidateUrl: string | undefined): boolean {
  const current = parseUrl(currentUrl);
  const candidate = parseUrl(candidateUrl);
  if (!current || !candidate) return false;

  current.hash = '';
  candidate.hash = '';
  return current.href === candidate.href;
}

function isSameRendererOrigin(currentUrl: string, candidateOrigin: string | undefined): boolean {
  const current = parseUrl(currentUrl);
  const candidate = parseUrl(candidateOrigin);
  if (!current || !candidate) return false;

  if (current.protocol === 'file:') {
    return candidate.protocol === 'file:';
  }

  return candidate.origin === current.origin;
}

function hasTrustedMediaContext(context: AccordLockMediaPermissionContext): boolean {
  if (context.permission !== 'media' || context.isMainFrame !== true) return false;
  if (!isSameRendererDocument(context.currentUrl, context.requestingUrl)) return false;
  return (
    context.securityOrigin === undefined ||
    isSameRendererOrigin(context.currentUrl, context.securityOrigin)
  );
}

export function shouldGrantAccordLockMicrophoneCheck(
  check: AccordLockMediaPermissionCheck
): boolean {
  return (
    hasTrustedMediaContext(check) &&
    check.mediaType === 'audio' &&
    isSameRendererOrigin(check.currentUrl, check.requestingOrigin)
  );
}

export function shouldGrantAccordLockMicrophoneRequest(
  request: AccordLockMediaPermissionRequest
): boolean {
  return (
    hasTrustedMediaContext(request) &&
    request.mediaTypes?.length === 1 &&
    request.mediaTypes[0] === 'audio'
  );
}
