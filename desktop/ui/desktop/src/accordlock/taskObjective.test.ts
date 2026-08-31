import { describe, expect, it } from 'vitest';
import { ACCORDLOCK_MAX_OBJECTIVE_BYTES, validateAccordLockObjective } from './taskObjective';

describe('validateAccordLockObjective', () => {
  it('returns the normalized objective used by approval and execution', () => {
    expect(validateAccordLockObjective('  Ship the release\n')).toEqual({
      ok: true,
      objective: 'Ship the release',
    });
  });

  it('rejects an empty or image-only objective before session creation', () => {
    expect(validateAccordLockObjective(' \n\t ')).toEqual({ ok: false, reason: 'EMPTY' });
  });

  it('measures the UTF-8 protocol limit in bytes rather than characters', () => {
    expect(validateAccordLockObjective('a'.repeat(ACCORDLOCK_MAX_OBJECTIVE_BYTES)).ok).toBe(true);
    expect(validateAccordLockObjective('x'.repeat(ACCORDLOCK_MAX_OBJECTIVE_BYTES + 1))).toEqual({
      ok: false,
      reason: 'TOO_LARGE',
    });
  });

  it('rejects control and bidi override characters', () => {
    expect(validateAccordLockObjective('Deploy\u0000now')).toEqual({
      ok: false,
      reason: 'UNSAFE_TEXT',
    });
    expect(validateAccordLockObjective('Deploy \u202etxt.exe')).toEqual({
      ok: false,
      reason: 'UNSAFE_TEXT',
    });
  });
});
