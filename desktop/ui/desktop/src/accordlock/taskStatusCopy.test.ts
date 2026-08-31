import { describe, expect, it } from 'vitest';
import { FIXED_TASK_REASON_CODES, taskStatusCopyForReason } from './taskStatusCopy';

describe('taskStatusCopyForReason', () => {
  it('provides fixed consequence-first copy for every supported reason code', () => {
    expect(FIXED_TASK_REASON_CODES.length).toBeGreaterThan(5);
    for (const reasonCode of FIXED_TASK_REASON_CODES) {
      const copy = taskStatusCopyForReason(reasonCode);
      expect(copy.title).not.toBe('');
      expect(copy.explanation).not.toBe('');
      if (reasonCode !== 'EXECUTED') expect(copy.nextStep).not.toBe('');
    }
  });

  it('describes the execution record without claiming the action itself was verified', () => {
    expect(taskStatusCopyForReason('EXECUTED')).toEqual({
      title: 'Action recorded',
      explanation: 'The execution record is valid.',
      nextStep: '',
    });
  });

  it('uses a safe fixed fallback instead of exposing an unknown runtime message', () => {
    expect(taskStatusCopyForReason('UNRECOGNIZED_CODE')).toEqual({
      title: 'Check result',
      explanation: 'The result could not be verified.',
      nextStep: 'Open verification details.',
    });
  });
});
