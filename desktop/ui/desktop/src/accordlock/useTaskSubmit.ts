import { useCallback, useEffect, useRef } from 'react';
import { AppEvents } from '../constants/events';
import type { UserInput } from '../types/message';
import type { AccordLockTaskAuthorizationState } from './taskAuthorizationStore';
import { validateAccordLockObjective } from './taskObjective';

export type TaskSubmissionResult =
  | 'SUBMITTED'
  | 'TASK_AUTHORIZATION_REQUESTED'
  | 'ALREADY_PENDING'
  | 'INVALID_TASK';

interface UseTaskSubmitOptions {
  sessionId: string;
  authorization: AccordLockTaskAuthorizationState;
  submit: (input: UserInput) => void;
}

export function useTaskSubmit({ sessionId, authorization, submit }: UseTaskSubmitOptions) {
  const pendingSubmission = useRef<UserInput | null>(null);

  useEffect(() => {
    if (authorization === 'REJECTED') {
      pendingSubmission.current = null;
      return;
    }
    if (authorization !== 'APPROVED' || !pendingSubmission.current) return;

    const input = pendingSubmission.current;
    pendingSubmission.current = null;
    submit(input);
  }, [authorization, submit]);

  return useCallback(
    (input: UserInput) => {
      if (authorization === 'APPROVED') {
        submit(input);
        return 'SUBMITTED' as const;
      }
      if (pendingSubmission.current) return 'ALREADY_PENDING' as const;

      const objective = validateAccordLockObjective(input.msg);
      if (!objective.ok || input.images.length > 0) return 'INVALID_TASK' as const;

      pendingSubmission.current = { ...input, msg: objective.objective };
      window.dispatchEvent(
        new CustomEvent(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST, {
          detail: { sessionId, objective: objective.objective },
        })
      );
      return 'TASK_AUTHORIZATION_REQUESTED' as const;
    },
    [authorization, sessionId, submit]
  );
}
