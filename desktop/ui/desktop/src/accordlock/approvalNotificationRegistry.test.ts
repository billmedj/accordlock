import { describe, expect, it, vi } from 'vitest';
import { ApprovalNotificationRegistry } from './approvalNotificationRegistry';

const closable = () => ({ close: vi.fn() });

describe('ApprovalNotificationRegistry', () => {
  it('closes a replaced notification and ignores a late close event from it', () => {
    const registry = new ApprovalNotificationRegistry(2);
    const first = closable();
    const replacement = closable();

    registry.register('approval-1', first);
    registry.register('approval-1', replacement);
    registry.release('approval-1', first);

    expect(first.close).toHaveBeenCalledOnce();
    expect(registry.size).toBe(1);
    expect(registry.dismiss('approval-1')).toBe(true);
    expect(replacement.close).toHaveBeenCalledOnce();
  });

  it('bounds alerts by closing the oldest one without retaining stale ownership', () => {
    const registry = new ApprovalNotificationRegistry(2);
    const first = closable();
    const second = closable();
    const third = closable();

    registry.register('approval-1', first);
    registry.register('approval-2', second);
    registry.register('approval-3', third);

    expect(first.close).toHaveBeenCalledOnce();
    expect(registry.size).toBe(2);
    expect(registry.dismiss('approval-1')).toBe(false);
    registry.clear();
    expect(second.close).toHaveBeenCalledOnce();
    expect(third.close).toHaveBeenCalledOnce();
    expect(registry.size).toBe(0);
  });
});
