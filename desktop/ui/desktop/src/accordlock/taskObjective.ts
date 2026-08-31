export const ACCORDLOCK_MAX_OBJECTIVE_BYTES = 4_000;

export type AccordLockObjectiveValidation =
  | { ok: true; objective: string }
  | { ok: false; reason: 'EMPTY' | 'TOO_LARGE' | 'UNSAFE_TEXT' };

/**
 * Normalize the exact task objective that is hashed and sent to the agent.
 * Keeping those three representations identical avoids an intent-binding gap.
 */
export function validateAccordLockObjective(value: string): AccordLockObjectiveValidation {
  const objective = value.trim();
  if (!objective) return { ok: false, reason: 'EMPTY' };

  // Match the main-process protocol rules and reject invisible bidi controls
  // that could make user-provided text appear different in the authorization surface.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(objective)) {
    return { ok: false, reason: 'UNSAFE_TEXT' };
  }

  if (new TextEncoder().encode(objective).byteLength > ACCORDLOCK_MAX_OBJECTIVE_BYTES) {
    return { ok: false, reason: 'TOO_LARGE' };
  }
  return { ok: true, objective };
}
