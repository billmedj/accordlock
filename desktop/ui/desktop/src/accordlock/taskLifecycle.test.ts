import { describe, expect, it, vi } from 'vitest';
import { stopAndRevokeTask } from './taskLifecycle';

describe('stopAndRevokeTask', () => {
  it('stops the model before starting revocation', async () => {
    const order: string[] = [];
    const stop = vi.fn(() => order.push('stop'));
    const revoke = vi.fn(async () => {
      order.push('revoke');
    });

    await stopAndRevokeTask('session-1', stop, revoke);

    expect(order).toEqual(['stop', 'revoke']);
    expect(stop).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith('session-1');
  });

  it('keeps the model stopped when revocation cannot be confirmed', async () => {
    const stop = vi.fn();
    const revoke = vi.fn(async () => {
      throw new Error('runtime unavailable');
    });

    await expect(stopAndRevokeTask('session-1', stop, revoke)).rejects.toThrow(
      'runtime unavailable'
    );
    expect(stop).toHaveBeenCalledOnce();
  });
});
