import { describe, expect, it, vi } from 'vitest';
import { AccordLockDecisionSingleFlight } from './decisionSingleFlight';

describe('AccordLockDecisionSingleFlight', () => {
  it('opens one native flow for identical concurrent decisions', async () => {
    const gate = new AccordLockDecisionSingleFlight();
    let complete: ((value: string) => void) | undefined;
    const operation = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          complete = resolve;
        })
    );

    const first = gate.run('approval-1', 'APPROVE', operation);
    const retry = gate.run('approval-1', 'APPROVE', operation);
    await vi.waitFor(() => expect(operation).toHaveBeenCalledOnce());
    complete?.('approved');

    await expect(first).resolves.toBe('approved');
    await expect(retry).resolves.toBe('approved');
    expect(operation).toHaveBeenCalledOnce();
  });

  it('rejects a contradictory decision and releases the key after settlement', async () => {
    const gate = new AccordLockDecisionSingleFlight();
    let complete: (() => void) | undefined;
    const first = gate.run(
      'approval-1',
      'APPROVE',
      () =>
        new Promise<void>((resolve) => {
          complete = resolve;
        })
    );

    await expect(gate.run('approval-1', 'REJECT', async () => undefined)).rejects.toThrow(
      'different authorization decision'
    );
    complete?.();
    await first;
    await expect(gate.run('approval-1', 'REJECT', async () => 'revoke')).resolves.toBe('revoke');
  });
});
