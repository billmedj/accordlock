import { describe, expect, it } from 'vitest';
import type { AccordLockTaskAuthorization } from './taskIpc';
import {
  buildTaskIntentBrief,
  extractUserLimits,
  literalBlockingUserLimit,
  relevantUserLimits,
  type IntentActionKind,
} from './taskIntent';

function authorization(
  objective = 'Update the release notes without changing package files.'
): AccordLockTaskAuthorization {
  return {
    protocol: 'accordlock.desktop.control/v2',
    schema_version: 2,
    authorization_id: '11111111-1111-4111-8111-111111111111',
    task_id: '22222222-2222-4222-8222-222222222222',
    session_id: 'session-1',
    authorization_digest: `sha256:${'1'.repeat(64)}`,
    objective,
    workspace_root: 'C:\\work\\release',
    prepared_at: 1,
    expires_at: 2,
    task_policy: {
      schema_version: 2,
      task_objective_hash: `sha256:${'2'.repeat(64)}`,
      preauthorized_capabilities: [
        { extension_id: 'developer', tool_name: 'read' },
        { extension_id: 'developer', tool_name: 'tree' },
      ],
      protected_paths: ['.env'],
    },
    task_policy_hash: `sha256:${'3'.repeat(64)}`,
    capabilities: [
      {
        extension_id: 'developer',
        tool_name: 'read',
        display_name: 'Read files',
        operation_type: 'READ',
      },
      {
        extension_id: 'developer',
        tool_name: 'tree',
        display_name: 'Browse workspace',
        operation_type: 'READ',
      },
      {
        extension_id: 'developer',
        tool_name: 'edit',
        display_name: 'Edit files',
        operation_type: 'WRITE',
      },
      {
        extension_id: 'developer',
        tool_name: 'shell',
        display_name: 'Run approved programs',
        operation_type: 'EXECUTE',
      },
    ],
  };
}

describe('extractUserLimits', () => {
  it('keeps literal user-written limits without paraphrasing them', () => {
    const objective =
      'Update the release notes. Do not change package files. Work without network access.';

    expect(extractUserLimits(objective)).toEqual([
      'Do not change package files.',
      'Work without network access.',
    ]);
  });

  it('does not manufacture limits from ordinary task prose', () => {
    expect(extractUserLimits('Review the code and write a short report.')).toEqual([]);
  });

  it('bounds the review surface', () => {
    expect(extractUserLimits("Don't edit A. Never edit B. Avoid C. Only inspect D.", 2)).toEqual([
      "Don't edit A.",
      'Never edit B.',
    ]);
  });
});

describe('buildTaskIntentBrief', () => {
  it('projects the exact objective and actual permission boundary', () => {
    const brief = buildTaskIntentBrief(authorization());

    expect(brief.outcome).toBe('Update the release notes without changing package files.');
    expect(brief.workspace).toBe('C:\\work\\release');
    expect(brief.automatic).toEqual(['Read files', 'Browse workspace']);
    expect(brief.requiresApproval).toEqual(['Edit files', 'Run approved programs']);
    expect(brief.unavailable).toEqual([
      'Network access',
      'Administrator access',
      'Protected settings and credentials',
    ]);
    expect(brief.userLimits).toEqual(['Update the release notes without changing package files.']);
  });

  it('projects controlled network access as approval-bound only when configured', () => {
    const configured = authorization();
    configured.capabilities.unshift({
      extension_id: 'accordlock_network',
      tool_name: 'https_request',
      display_name: 'Read approved websites',
      operation_type: 'NETWORK',
    });
    const brief = buildTaskIntentBrief(configured);

    expect(brief.requiresApproval).toContain('Read approved websites');
    expect(brief.automatic).not.toContain('Read approved websites');
    expect(brief.unavailable).not.toContain('Network access');
    expect(brief.unavailable).toContain('Administrator access');
  });
});

describe('relevantUserLimits', () => {
  it('resurfaces exact file limits when a file change is proposed', () => {
    expect(
      relevantUserLimits(
        'Prepare the release. Do not change package files. Never run deployment commands.',
        'edit'
      )
    ).toEqual(['Do not change package files.']);
  });

  it('resurfaces exact command limits when a command is proposed', () => {
    expect(
      relevantUserLimits(
        'Prepare the release. Do not change package files. Never run deployment commands.',
        'shell'
      )
    ).toEqual(['Never run deployment commands.']);
  });

  it('resurfaces exact network limits when an HTTPS request is proposed', () => {
    expect(
      relevantUserLimits(
        'Check the release. Do not contact production systems. Never send data outside this folder.',
        'https_request'
      )
    ).toEqual(['Do not contact production systems.', 'Never send data outside this folder.']);
  });
});

describe('literalBlockingUserLimit', () => {
  it.each([
    ['Do not change files.', 'write'],
    ["Don't modify any files.", 'edit'],
    ['Never delete the files.', 'delete_file'],
    ['Review this folder and do not change files.', 'shell'],
    ['Make no file changes.', 'write'],
    ['This task is read-only.', 'edit'],
    ['Only inspect this repository.', 'delete_file'],
    ['Do not run commands.', 'shell'],
    ['Never use the terminal.', 'shell'],
    ['No shell access.', 'shell'],
    ['Work without network access.', 'https_request'],
    ['Do not use the internet.', 'https_request'],
    ['Stay offline.', 'https_request'],
  ] as const)('blocks %s for %s', (objective, action) => {
    expect(literalBlockingUserLimit(objective, action)).toBe(objective);
  });

  it('blocks shell execution when the task categorically bans file changes', () => {
    expect(literalBlockingUserLimit('Review the folder. Do not change files.', 'shell')).toBe(
      'Do not change files.'
    );
  });

  it.each([
    ['Do not change package files.', 'write'],
    ['Do not make changes to package files.', 'write'],
    ['Do not modify files in src.', 'edit'],
    ['Do not delete files except generated.log.', 'delete_file'],
    ['Never run deployment commands.', 'shell'],
    ['Do not use the terminal in production.', 'shell'],
    ['Do not access the internet except docs.example.com.', 'https_request'],
    ['Review the read-only fixture.', 'edit'],
    ['Inspect files and write a report.', 'write'],
    ["Explain why 'do not change files' is too strict.", 'write'],
    ['Document the phrase “never use the terminal”.', 'shell'],
  ] as const)(
    'does not turn scoped or descriptive wording into a global ban: %s',
    (objective, action) => {
      expect(literalBlockingUserLimit(objective, action as IntentActionKind)).toBeNull();
    }
  );

  it('does not apply one categorical class to unrelated actions', () => {
    expect(literalBlockingUserLimit('Do not run commands.', 'write')).toBeNull();
    expect(literalBlockingUserLimit('Do not use the internet.', 'edit')).toBeNull();
    expect(literalBlockingUserLimit('Do not change files.', 'https_request')).toBeNull();
  });

  it('returns the first exact applicable sentence without paraphrasing it', () => {
    expect(
      literalBlockingUserLimit(
        'Review the folder. Never use the terminal. Do not change files.',
        'shell'
      )
    ).toBe('Never use the terminal.');
  });

  it('does not stop enforcing after the bounded set shown in the compact review', () => {
    const reminders = Array.from({ length: 13 }, (_, index) => `Avoid temporary item ${index}.`);
    const objective = `${reminders.join(' ')} Do not change files.`;

    expect(extractUserLimits(objective)).toHaveLength(3);
    expect(literalBlockingUserLimit(objective, 'write')).toBe('Do not change files.');
  });
});
