import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppEvents } from '../constants/events';
import type { UserInput } from '../types/message';
import type { AccordLockTaskAuthorizationState } from './taskAuthorizationStore';
import { useTaskSubmit } from './useTaskSubmit';

const input: UserInput = { msg: '  Update the release notes.  ', images: [] };

describe('useTaskSubmit', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('holds the first message locally until the exact session is approved', () => {
    const submit = vi.fn();
    const dispatch = vi.spyOn(window, 'dispatchEvent');
    const { result, rerender } = renderHook(
      ({ authorization }: { authorization: AccordLockTaskAuthorizationState }) =>
        useTaskSubmit({ sessionId: 'session-1', authorization, submit }),
      {
        initialProps: {
          authorization: 'PENDING' as AccordLockTaskAuthorizationState,
        },
      }
    );

    act(() => result.current(input));

    expect(submit).not.toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledOnce();
    const event = dispatch.mock.calls[0][0] as CustomEvent;
    expect(event.type).toBe(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST);
    expect(event.detail).toEqual({
      sessionId: 'session-1',
      objective: 'Update the release notes.',
    });

    rerender({ authorization: 'APPROVED' });
    expect(submit).toHaveBeenCalledOnce();
    expect(submit).toHaveBeenCalledWith({ ...input, msg: 'Update the release notes.' });
  });

  it('does not queue duplicate sends while an approval is pending', () => {
    const submit = vi.fn();
    const dispatch = vi.spyOn(window, 'dispatchEvent');
    const { result } = renderHook(() =>
      useTaskSubmit({ sessionId: 'session-1', authorization: 'PENDING', submit })
    );

    act(() => {
      result.current(input);
      result.current({ msg: 'A different request', images: [] });
    });

    expect(dispatch).toHaveBeenCalledOnce();
    expect(submit).not.toHaveBeenCalled();
  });

  it('drops refused input and allows a fresh task request', () => {
    const submit = vi.fn();
    const dispatch = vi.spyOn(window, 'dispatchEvent');
    const { result, rerender } = renderHook(
      ({ authorization }) => useTaskSubmit({ sessionId: 'session-1', authorization, submit }),
      { initialProps: { authorization: 'PENDING' as 'PENDING' | 'REJECTED' } }
    );

    act(() => result.current(input));
    rerender({ authorization: 'REJECTED' });
    act(() => result.current({ msg: 'Use a safer plan.', images: [] }));

    expect(dispatch).toHaveBeenCalledTimes(2);
    expect((dispatch.mock.calls[1][0] as CustomEvent).detail.objective).toBe('Use a safer plan.');
    expect(submit).not.toHaveBeenCalled();
  });

  it('submits immediately once authority already exists', () => {
    const submit = vi.fn();
    const dispatch = vi.spyOn(window, 'dispatchEvent');
    const { result } = renderHook(() =>
      useTaskSubmit({ sessionId: 'session-1', authorization: 'APPROVED', submit })
    );

    act(() => result.current(input));

    expect(submit).toHaveBeenCalledWith(input);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('does not create an unbound fallback task for images or empty text', () => {
    const submit = vi.fn();
    const dispatch = vi.spyOn(window, 'dispatchEvent');
    const { result } = renderHook(() =>
      useTaskSubmit({ sessionId: 'session-1', authorization: 'PENDING', submit })
    );

    let emptyResult: ReturnType<typeof result.current> | undefined;
    let imageResult: ReturnType<typeof result.current> | undefined;
    act(() => {
      emptyResult = result.current({ msg: '  ', images: [] });
      imageResult = result.current({
        msg: 'Use this image',
        images: [{ data: 'base64', mimeType: 'image/png' }],
      });
    });

    expect(emptyResult).toBe('INVALID_TASK');
    expect(imageResult).toBe('INVALID_TASK');
    expect(dispatch).not.toHaveBeenCalled();
    expect(submit).not.toHaveBeenCalled();
  });
});
