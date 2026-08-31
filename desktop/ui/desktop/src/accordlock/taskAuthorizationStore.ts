import { useSyncExternalStore } from 'react';

export type AccordLockTaskAuthorizationState = 'PENDING' | 'APPROVED' | 'REJECTED';

const states = new Map<string, AccordLockTaskAuthorizationState>();
const expiries = new Map<string, number>();
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

export function setAccordLockTaskAuthorization(
  sessionId: string,
  state: AccordLockTaskAuthorizationState,
  expiresAt?: number
): void {
  const previousState = states.get(sessionId);
  const previousExpiry = expiries.get(sessionId);
  states.set(sessionId, state);
  if (state === 'APPROVED') {
    if (expiresAt !== undefined) {
      expiries.set(sessionId, expiresAt);
    } else {
      expiries.delete(sessionId);
    }
  } else {
    expiries.delete(sessionId);
  }
  if (previousState === state && previousExpiry === expiries.get(sessionId)) return;
  notify();
}

export function getAccordLockTaskAuthorization(
  sessionId: string
): AccordLockTaskAuthorizationState {
  const state = states.get(sessionId) ?? 'PENDING';
  if (state !== 'APPROVED') return state;
  const expiresAt = expiries.get(sessionId);
  return expiresAt !== undefined && expiresAt > Math.floor(Date.now() / 1_000)
    ? 'APPROVED'
    : 'REJECTED';
}

export function clearAccordLockTaskAuthorization(sessionId: string): void {
  const stateChanged = states.delete(sessionId);
  const expiryChanged = expiries.delete(sessionId);
  if (stateChanged || expiryChanged) notify();
}

export function getAccordLockTaskAuthorizationExpiry(sessionId: string): number | null {
  return expiries.get(sessionId) ?? null;
}

export function useAccordLockTaskAuthorized(sessionId: string): boolean {
  return useAccordLockTaskAuthorization(sessionId) === 'APPROVED';
}

export function useAccordLockTaskAuthorization(
  sessionId: string
): AccordLockTaskAuthorizationState {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => getAccordLockTaskAuthorization(sessionId),
    () => 'PENDING'
  );
}

export function useAccordLockTaskAuthorizationExpiry(sessionId: string): number | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => getAccordLockTaskAuthorizationExpiry(sessionId),
    () => null
  );
}
