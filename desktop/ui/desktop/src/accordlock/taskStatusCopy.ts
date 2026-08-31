export type TaskStatusCopy = {
  title: string;
  explanation: string;
  nextStep: string;
};

const COPY_BY_REASON_CODE: Readonly<Record<string, TaskStatusCopy>> = {
  EXECUTED: {
    title: 'Action recorded',
    explanation: 'The execution record is valid.',
    nextStep: '',
  },
  ACTION_APPROVAL_REQUIRED: {
    title: 'Approval required',
    explanation: 'This action needs approval.',
    nextStep: 'Review the requested action.',
  },
  ACTION_APPROVAL_DENIED: {
    title: 'Not approved',
    explanation: 'The action did not run.',
    nextStep: 'Change the request or continue without this action.',
  },
  ACTION_APPROVAL_EXPIRED: {
    title: 'Approval expired',
    explanation: "The action didn't run before its approval expired.",
    nextStep: 'Review a fresh request before trying again.',
  },
  ACTION_APPROVAL_ALREADY_USED: {
    title: 'Approval already used',
    explanation: 'This approval cannot be reused.',
    nextStep: 'Review a fresh request before trying again.',
  },
  TASK_AUTHORIZATION_REQUIRED: {
    title: 'Task approval required',
    explanation: 'Task access was not approved.',
    nextStep: 'Review task access.',
  },
  TASK_AUTHORIZATION_EXPIRED: {
    title: 'Task access expired',
    explanation: 'Approved access has ended.',
    nextStep: 'Start a new task review before work continues.',
  },
  EXECUTION_UNKNOWN: {
    title: 'Check result',
    explanation: 'AccordLock could not confirm whether the action ran.',
    nextStep: 'Inspect the target state before approving any retry.',
  },
  NETWORK_EXECUTION_UNKNOWN: {
    title: 'Check network result',
    explanation: 'AccordLock could not confirm the network action.',
    nextStep: 'Check the remote system before approving any retry.',
  },
  RUNTIME_UNAVAILABLE: {
    title: 'Actions paused',
    explanation: 'AccordLock is reconnecting.',
    nextStep: 'Try again in a moment.',
  },
  DENIED: {
    title: 'Action blocked',
    explanation: 'Blocked by policy.',
    nextStep: 'Change the request or contact your administrator.',
  },
  POLICY_DENIED: {
    title: 'Action blocked',
    explanation: 'Blocked by policy.',
    nextStep: 'Change the request or contact your administrator.',
  },
};

const FALLBACK_COPY: TaskStatusCopy = {
  title: 'Check result',
  explanation: 'The result could not be verified.',
  nextStep: 'Open verification details.',
};

export function taskStatusCopyForReason(reasonCode: string): TaskStatusCopy {
  return COPY_BY_REASON_CODE[reasonCode] ?? FALLBACK_COPY;
}

export const FIXED_TASK_REASON_CODES = Object.freeze(Object.keys(COPY_BY_REASON_CODE));
