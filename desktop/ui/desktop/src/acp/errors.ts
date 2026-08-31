import { RequestError } from '@agentclientprotocol/sdk';
import { userFacingErrorMessage } from '../utils/conversionUtils';

export interface AcpCreditsExhaustedError {
  message: string;
  url?: string;
}

const CREDITS_EXHAUSTED_REASON = 'credits_exhausted';
const AUTH_REQUIRED_CODE = -32000;
const CREDITS_EXHAUSTED_MESSAGE =
  'This provider account has no available credits. Add credits with the provider, then try again.';
export const ACP_REQUEST_FAILED_MESSAGE =
  'AccordLock could not complete this request. Try again. If the problem continues, check the provider connection in Settings.';

// Kept in sync with RECIPE_PARAMS_CANCELLED_REASON in crates/goose/src/acp/server/recipe.rs.
const RECIPE_PARAMS_CANCELLED_REASON = 'recipe_params_cancelled';

export const RECIPE_PARAMETER_SCOPES_UNSUPPORTED_MESSAGE =
  'The connected agent backend does not support securely scoped recipe parameters. Update AccordLock or the backend and try again.';

export class RecipeParameterScopesUnsupportedError extends Error {
  constructor() {
    super(RECIPE_PARAMETER_SCOPES_UNSUPPORTED_MESSAGE);
    this.name = 'RecipeParameterScopesUnsupportedError';
  }
}

export function isRecipeParameterScopesUnsupported(
  error: unknown
): error is RecipeParameterScopesUnsupportedError {
  return error instanceof RecipeParameterScopesUnsupportedError;
}

export function isRecipeParamsCancelled(error: unknown): boolean {
  return asAcpJsonRpcError(error)?.data?.reason === RECIPE_PARAMS_CANCELLED_REASON;
}

export function parseAcpCreditsExhaustedError(error: unknown): AcpCreditsExhaustedError | null {
  const jsonRpcError = asAcpJsonRpcError(error);
  if (jsonRpcError?.data?.reason !== CREDITS_EXHAUSTED_REASON) {
    return null;
  }

  const url = typeof jsonRpcError.data.url === 'string' ? jsonRpcError.data.url : undefined;

  return {
    message: CREDITS_EXHAUSTED_MESSAGE,
    ...(url ? { url } : {}),
  };
}

export function formatAcpError(error: unknown): string {
  if (error instanceof RequestError && error.code === AUTH_REQUIRED_CODE) {
    return 'Sign in to your provider, then try again.';
  }
  return userFacingErrorMessage(error, ACP_REQUEST_FAILED_MESSAGE);
}

interface AcpJsonRpcError {
  message: string;
  data: Record<string, unknown>;
}

function asAcpJsonRpcError(error: unknown): AcpJsonRpcError | null {
  if (!isRecord(error)) {
    return null;
  }

  const candidate = isRecord(error.error) ? error.error : error;
  if (typeof candidate.message !== 'string' || !isRecord(candidate.data)) {
    return null;
  }

  return {
    message: candidate.message,
    data: candidate.data,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function acpErrorMessage(error: unknown): string | null {
  if (!isRecord(error)) {
    return null;
  }

  const candidate = 'error' in error && isRecord(error.error) ? error.error : error;
  if (!isRecord(candidate)) {
    return null;
  }
  if (typeof candidate.data === 'string') {
    return candidate.data;
  }
  return typeof candidate.message === 'string' ? candidate.message : null;
}

export function normalizeAcpError(error: unknown, fallback: string): Error {
  const message = acpErrorMessage(error);
  if (message) {
    return new Error(message);
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error(fallback);
}
