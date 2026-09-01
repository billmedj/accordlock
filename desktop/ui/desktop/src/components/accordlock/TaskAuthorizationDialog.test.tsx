import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AccordLockTaskBridge } from '../../accordlock/taskBridge';
import {
  clearAccordLockTaskAuthorization,
  getAccordLockTaskAuthorization,
  getAccordLockTaskAuthorizationExpiry,
  setAccordLockTaskAuthorization,
} from '../../accordlock/taskAuthorizationStore';
import {
  parseAccordLockTaskAuthorization,
  type AccordLockTaskAuthorization,
  type AccordLockTaskAuthorizationDecisionAck,
} from '../../accordlock/taskAuthorizationContract';
import { ACCORDLOCK_CONTROL_PROTOCOL } from '../../accordlock/taskIpc';
import { AppEvents } from '../../constants/events';
import { IntlTestWrapper } from '../../i18n/test-utils';
import { TaskAuthorizationController } from './TaskAuthorizationController';
import { TaskAuthorizationDialog, type AccordLockAutonomyMode } from './TaskAuthorizationDialog';

const authorizationDigest = `sha256:${'a'.repeat(64)}`;
const decisionRecordDigest = `sha256:${'b'.repeat(64)}`;

const authorization: AccordLockTaskAuthorization = {
  protocol: ACCORDLOCK_CONTROL_PROTOCOL,
  schema_version: 2,
  authorization_id: '11111111-1111-4111-8111-111111111111',
  task_id: '22222222-2222-4222-8222-222222222222',
  session_id: 'session-authorization',
  authorization_digest: authorizationDigest,
  objective: 'Prepare the release without changing files outside the selected project.',
  workspace_root: 'C:\\Work\\accordlock',
  prepared_at: 1_999_996_400,
  expires_at: 2_000_000_000,
  task_policy: {
    schema_version: 2,
    task_objective_hash: `sha256:${'c'.repeat(64)}`,
    preauthorized_capabilities: [{ extension_id: 'developer', tool_name: 'read' }],
    protected_paths: ['.accordlock', '.git'],
  },
  task_policy_hash: `sha256:${'d'.repeat(64)}`,
  capabilities: [
    {
      extension_id: 'developer',
      tool_name: 'read',
      display_name: 'Read project files',
      description: 'Inspect files inside the selected workspace.',
      operation_type: 'READ',
    },
    {
      extension_id: 'developer',
      tool_name: 'write',
      display_name: 'Edit project files',
      operation_type: 'WRITE',
    },
  ],
};

const acknowledgementFor = (
  authorizedTask: AccordLockTaskAuthorization,
  status: 'APPROVED' | 'REJECTED'
): AccordLockTaskAuthorizationDecisionAck => ({
  protocol: ACCORDLOCK_CONTROL_PROTOCOL,
  schema_version: 2,
  authorization_id: authorizedTask.authorization_id,
  task_id: authorizedTask.task_id,
  reviewed_authorization_digest: authorizedTask.authorization_digest,
  authorization_digest: authorizedTask.authorization_digest,
  status,
  reason_code: status === 'APPROVED' ? 'SESSION_APPROVED' : 'TASK_AUTHORIZATION_REJECTED',
  reason: status === 'APPROVED' ? 'Task scope recorded.' : 'Task refused.',
  decision_record: {
    record_id: `decision-record-${authorizedTask.authorization_id}`,
    record_digest: decisionRecordDigest,
    recorded_at: 2_000_000_001,
  },
});

const deferred = <T,>() => {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
};

const renderDialog = (
  submitDecision: (
    request: Parameters<AccordLockTaskBridge['submitTaskAuthorizationDecision']>[0]
  ) => Promise<unknown>,
  options: {
    onResolved?: () => void;
    onProtocolError?: (message: string) => void;
    persistAutonomyMode?: (mode: AccordLockAutonomyMode) => Promise<void>;
    authorization?: AccordLockTaskAuthorization;
  } = {}
) =>
  render(
    <IntlTestWrapper>
      <TaskAuthorizationDialog
        authorization={options.authorization ?? authorization}
        submitDecision={submitDecision}
        onResolved={options.onResolved ?? vi.fn()}
        onProtocolError={options.onProtocolError ?? vi.fn()}
        persistAutonomyMode={options.persistAutonomyMode}
      />
    </IntlTestWrapper>
  );

describe('TaskAuthorizationDialog', () => {
  it('hands a verified authorization directly to the trusted confirmation', async () => {
    const decision = deferred<unknown>();
    const persistAutonomyMode = vi.fn().mockResolvedValue(undefined);
    const submitDecision = vi.fn().mockReturnValue(decision.promise);

    renderDialog(submitDecision, { persistAutonomyMode });

    expect(screen.getByRole('dialog')).toHaveAccessibleName('Opening task review…');
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription(
      'Review the folder and allowed actions.'
    );
    expect(screen.getByText(authorization.objective)).toBeInTheDocument();
    expect(screen.queryByText(authorization.workspace_root)).not.toBeInTheDocument();
    expect(screen.queryByText('Read project files')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /start|approve/i })).not.toBeInTheDocument();

    await waitFor(() => expect(persistAutonomyMode).toHaveBeenCalledWith('AUTONOMOUS'));
    await waitFor(() =>
      expect(submitDecision).toHaveBeenCalledWith({
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        authorization_id: authorization.authorization_id,
        task_id: authorization.task_id,
        authorization_digest: authorization.authorization_digest,
        decision: 'APPROVE',
      })
    );
    expect(persistAutonomyMode.mock.invocationCallOrder[0]).toBeLessThan(
      submitDecision.mock.invocationCallOrder[0]
    );
  });

  it.each(['APPROVED', 'REJECTED'] as const)(
    'closes automatically after a valid %s record',
    async (status) => {
      const onResolved = vi.fn();
      const submitDecision = vi.fn().mockResolvedValue(acknowledgementFor(authorization, status));

      renderDialog(submitDecision, { onResolved });

      await waitFor(() => expect(onResolved).toHaveBeenCalledOnce());
      expect(submitDecision).toHaveBeenCalledWith(expect.objectContaining({ decision: 'APPROVE' }));
      expect(screen.queryByText(/Task approved|Task kept locked/)).not.toBeInTheDocument();
    }
  );

  it('accepts the effective authority sealed by the trusted native review', async () => {
    const onResolved = vi.fn();
    const submitDecision = vi.fn().mockResolvedValue({
      ...acknowledgementFor(authorization, 'APPROVED'),
      authorization_digest: `sha256:${'e'.repeat(64)}`,
    });

    renderDialog(submitDecision, { onResolved });

    await waitFor(() => expect(onResolved).toHaveBeenCalledOnce());
  });

  it('fails closed when the default work mode cannot be persisted, then retries safely', async () => {
    const persistAutonomyMode = vi
      .fn()
      .mockRejectedValueOnce(new Error('configuration unavailable'))
      .mockResolvedValue(undefined);
    const submitDecision = vi.fn().mockResolvedValue(acknowledgementFor(authorization, 'APPROVED'));
    const onResolved = vi.fn();
    const onProtocolError = vi.fn();
    renderDialog(submitDecision, { persistAutonomyMode, onResolved, onProtocolError });

    expect(await screen.findByRole('alert')).toHaveTextContent('Try again or cancel the task.');
    expect(submitDecision).not.toHaveBeenCalled();
    expect(onProtocolError).toHaveBeenCalledWith('configuration unavailable');

    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

    await waitFor(() => expect(onResolved).toHaveBeenCalledOnce());
    expect(persistAutonomyMode).toHaveBeenCalledTimes(2);
    expect(submitDecision).toHaveBeenCalledWith(expect.objectContaining({ decision: 'APPROVE' }));
  });

  it('records an explicit rejection when the user cancels after a failed handoff', async () => {
    const persistAutonomyMode = vi.fn().mockRejectedValue(new Error('configuration unavailable'));
    const submitDecision = vi.fn().mockResolvedValue(acknowledgementFor(authorization, 'REJECTED'));
    const onResolved = vi.fn();
    renderDialog(submitDecision, { persistAutonomyMode, onResolved });

    await screen.findByRole('alert');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel task' }));

    expect(await screen.findByRole('dialog')).toHaveAccessibleName('Cancelling task…');
    await waitFor(() => expect(onResolved).toHaveBeenCalledOnce());
    expect(submitDecision).toHaveBeenCalledOnce();
    expect(submitDecision).toHaveBeenCalledWith(expect.objectContaining({ decision: 'REJECT' }));
  });

  it('shows a retryable fail-closed state for a mismatched acknowledgement', async () => {
    const onResolved = vi.fn();
    const onProtocolError = vi.fn();
    const submitDecision = vi.fn().mockResolvedValue({
      ...acknowledgementFor(authorization, 'APPROVED'),
      reviewed_authorization_digest: `sha256:${'e'.repeat(64)}`,
    });
    renderDialog(submitDecision, { onResolved, onProtocolError });

    expect(await screen.findByRole('alert')).toHaveTextContent('Try again or cancel the task.');
    expect(onResolved).not.toHaveBeenCalled();
    expect(onProtocolError).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Cancel task' })).toBeEnabled();
  });

  it('never submits an expired authorization for approval', async () => {
    const persistAutonomyMode = vi.fn();
    const submitDecision = vi.fn();
    const onProtocolError = vi.fn();
    renderDialog(submitDecision, {
      persistAutonomyMode,
      onProtocolError,
      authorization: { ...authorization, expires_at: Math.floor(Date.now() / 1_000) - 1 },
    });

    await screen.findByRole('alert');
    expect(persistAutonomyMode).not.toHaveBeenCalled();
    expect(submitDecision).not.toHaveBeenCalled();
    expect(onProtocolError).toHaveBeenCalledWith(
      'Task authorization expired before confirmation opened'
    );
  });

  it('rejects an unsafe policy before any handoff can render', () => {
    expect(() =>
      parseAccordLockTaskAuthorization({
        ...authorization,
        task_policy: {
          ...authorization.task_policy,
          preauthorized_capabilities: [{ extension_id: 'developer', tool_name: 'write' }],
        },
      })
    ).toThrow();
    expect(() =>
      parseAccordLockTaskAuthorization({
        ...authorization,
        task_policy: {
          ...authorization.task_policy,
          protected_paths: ['.git', '.accordlock'],
        },
      })
    ).toThrow();
  });
});

describe('TaskAuthorizationController', () => {
  const sessionIds = [
    authorization.session_id,
    'session-prepare',
    'session-approved',
    'session-rejected',
    'session-duplicate',
    'session-queue-1',
    'session-queue-2',
    'session-deleted',
    'session-manual',
    'session-expired',
    'session-no-auto-submit',
  ];

  afterEach(() => {
    sessionIds.forEach(clearAccordLockTaskAuthorization);
  });

  const createBridge = (overrides: Partial<AccordLockTaskBridge> = {}): AccordLockTaskBridge => ({
    getTaskAudit: vi.fn().mockRejectedValue(new Error('No audit runtime')),
    getPendingTaskAuthorizations: vi.fn().mockResolvedValue(null),
    requestTaskAuthorization: vi.fn().mockResolvedValue(null),
    submitTaskAuthorizationDecision: vi.fn(() => new Promise<never>(() => undefined)),
    revokeTaskAuthorization: vi.fn().mockResolvedValue(null),
    restoreDeletedFile: vi.fn().mockResolvedValue(null),
    subscribeTaskAuthorizations: vi.fn(() => vi.fn()),
    reportProtocolError: vi.fn(),
    ...overrides,
  });

  it('rejects malformed projections and automatically hands off the next verified one', async () => {
    let listener: ((value: unknown) => void) | undefined;
    const bridge = createBridge({
      subscribeTaskAuthorizations: vi.fn((nextListener) => {
        listener = nextListener;
        return vi.fn();
      }),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );
    await waitFor(() => expect(bridge.getPendingTaskAuthorizations).toHaveBeenCalledOnce());

    act(() => listener?.({ ...authorization, unexpected_authority: true }));

    expect(await screen.findByText('Task blocked')).toBeInTheDocument();
    expect(bridge.reportProtocolError).toHaveBeenCalledWith(
      'Rejected malformed task authorization projection'
    );

    act(() => listener?.(parseAccordLockTaskAuthorization(authorization)));

    expect(await screen.findByText(authorization.objective)).toBeInTheDocument();
    await waitFor(() =>
      expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'APPROVE' })
      )
    );
    expect(screen.queryByText('Task blocked')).not.toBeInTheDocument();
  });

  it('prepares the exact initial task and opens trusted review without a renderer consent step', async () => {
    const sessionId = 'session-prepare';
    const preparedAuthorization = {
      ...authorization,
      session_id: sessionId,
      objective: 'Ship the protected desktop release.',
    };
    const bridge = createBridge({
      requestTaskAuthorization: vi.fn().mockResolvedValue(preparedAuthorization),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: {
            sessionId,
            initialMessage: { msg: '  Ship the protected desktop release.  ', images: [] },
          },
        })
      );
    });

    expect(getAccordLockTaskAuthorization(sessionId)).toBe('PENDING');
    await waitFor(() =>
      expect(bridge.requestTaskAuthorization).toHaveBeenCalledWith({
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        session_id: sessionId,
        objective: preparedAuthorization.objective,
      })
    );
    await waitFor(() =>
      expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledWith(
        expect.objectContaining({
          authorization_id: preparedAuthorization.authorization_id,
          decision: 'APPROVE',
        })
      )
    );
    expect(await screen.findByText(preparedAuthorization.objective)).toBeInTheDocument();
  });

  it('authorizes the text actually submitted instead of a prefilled draft', async () => {
    const sessionId = 'session-no-auto-submit';
    const submittedAuthorization = {
      ...authorization,
      session_id: sessionId,
      objective: 'Use the edited, safer objective.',
    };
    const bridge = createBridge({
      requestTaskAuthorization: vi.fn().mockResolvedValue(submittedAuthorization),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: {
            sessionId,
            initialMessage: { msg: 'Unsafe prefilled draft.', images: [] },
            noAutoSubmit: true,
          },
        })
      );
    });
    expect(bridge.requestTaskAuthorization).not.toHaveBeenCalled();

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST, {
          detail: { sessionId, objective: submittedAuthorization.objective },
        })
      );
    });

    await waitFor(() =>
      expect(bridge.requestTaskAuthorization).toHaveBeenCalledWith(
        expect.objectContaining({ objective: submittedAuthorization.objective })
      )
    );
    await waitFor(() => expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledOnce());
    expect(screen.queryByText('Unsafe prefilled draft.')).not.toBeInTheDocument();
  });

  it('publishes APPROVED only after the matching trusted acknowledgement', async () => {
    const sessionId = 'session-approved';
    const approvedAuthorization = { ...authorization, session_id: sessionId };
    const decision = deferred<unknown>();
    const bridge = createBridge({
      requestTaskAuthorization: vi.fn().mockResolvedValue(approvedAuthorization),
      submitTaskAuthorizationDecision: vi.fn().mockReturnValue(decision.promise),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: {
            sessionId,
            initialMessage: { msg: approvedAuthorization.objective, images: [] },
          },
        })
      );
    });

    await waitFor(() => expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledOnce());
    expect(getAccordLockTaskAuthorization(sessionId)).toBe('PENDING');
    await act(async () => decision.resolve(acknowledgementFor(approvedAuthorization, 'APPROVED')));
    await waitFor(() => expect(getAccordLockTaskAuthorization(sessionId)).toBe('APPROVED'));
    expect(getAccordLockTaskAuthorizationExpiry(sessionId)).toBe(approvedAuthorization.expires_at);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('publishes REJECTED and clears the draft when trusted review is cancelled', async () => {
    const sessionId = 'session-rejected';
    const rejectedAuthorization = { ...authorization, session_id: sessionId };
    const bridge = createBridge({
      requestTaskAuthorization: vi.fn().mockResolvedValue(rejectedAuthorization),
      submitTaskAuthorizationDecision: vi
        .fn()
        .mockResolvedValue(acknowledgementFor(rejectedAuthorization, 'REJECTED')),
    });
    const clearInitialMessage = vi.fn();
    window.addEventListener(AppEvents.CLEAR_INITIAL_MESSAGE, clearInitialMessage);
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: {
            sessionId,
            initialMessage: { msg: rejectedAuthorization.objective, images: [] },
          },
        })
      );
    });

    await waitFor(() => expect(getAccordLockTaskAuthorization(sessionId)).toBe('REJECTED'));
    expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledWith(
      expect.objectContaining({ decision: 'APPROVE' })
    );
    expect(clearInitialMessage).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { sessionId } })
    );
    window.removeEventListener(AppEvents.CLEAR_INITIAL_MESSAGE, clearInitialMessage);
  });

  it('drains verified authorizations in order, one trusted review at a time', async () => {
    const first = { ...authorization, session_id: 'session-queue-1' };
    const second: AccordLockTaskAuthorization = {
      ...authorization,
      authorization_id: '33333333-3333-4333-8333-333333333333',
      task_id: '44444444-4444-4444-8444-444444444444',
      session_id: 'session-queue-2',
      authorization_digest: `sha256:${'e'.repeat(64)}`,
      objective: 'Authorize the second queued task.',
      prepared_at: authorization.prepared_at + 1,
    };
    const firstDecision = deferred<unknown>();
    const bridge = createBridge({
      getPendingTaskAuthorizations: vi.fn().mockResolvedValue([first, second]),
      submitTaskAuthorizationDecision: vi.fn((request) =>
        request.authorization_id === first.authorization_id
          ? firstDecision.promise
          : Promise.resolve(acknowledgementFor(second, 'REJECTED'))
      ),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    expect(await screen.findByText(first.objective)).toBeInTheDocument();
    expect(screen.queryByText(second.objective)).not.toBeInTheDocument();
    await waitFor(() => expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledOnce());

    await act(async () => firstDecision.resolve(acknowledgementFor(first, 'REJECTED')));

    await waitFor(() => expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getAccordLockTaskAuthorization(first.session_id)).toBe('REJECTED'));
    await waitFor(() => expect(getAccordLockTaskAuthorization(second.session_id)).toBe('REJECTED'));
  });

  it('revokes a preparation that arrives after its session was deleted', async () => {
    const sessionId = 'session-deleted';
    const deletedAuthorization = { ...authorization, session_id: sessionId };
    const preparation = deferred<unknown>();
    const bridge = createBridge({
      requestTaskAuthorization: vi.fn().mockReturnValue(preparation.promise),
      revokeTaskAuthorization: vi.fn().mockResolvedValue({
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        session_id: sessionId,
        task_id: deletedAuthorization.task_id,
        run_id: sessionId,
        status: 'REVOKED',
        reason_code: 'NO_AUTHORIZATION_INSTALLED',
        revocation_record: { request_id: null, revocation_digest: null },
      }),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ACCORDLOCK_TASK_AUTHORIZATION_REQUEST, {
          detail: { sessionId, objective: deletedAuthorization.objective },
        })
      );
    });
    await waitFor(() => expect(bridge.requestTaskAuthorization).toHaveBeenCalledOnce());
    act(() => {
      window.dispatchEvent(new CustomEvent(AppEvents.SESSION_DELETED, { detail: { sessionId } }));
    });
    await act(async () => preparation.resolve(deletedAuthorization));

    await waitFor(() =>
      expect(bridge.revokeTaskAuthorization).toHaveBeenCalledWith({
        protocol: ACCORDLOCK_CONTROL_PROTOCOL,
        schema_version: 2,
        session_id: sessionId,
      })
    );
    expect(bridge.submitTaskAuthorizationDecision).not.toHaveBeenCalled();
  });

  it('rotates an expired authorization before opening trusted review', async () => {
    const sessionId = 'session-expired';
    const now = Math.floor(Date.now() / 1_000);
    const expiredAuthorization = {
      ...authorization,
      session_id: sessionId,
      prepared_at: now - 3_600,
      expires_at: now - 1,
    };
    const rotatedAuthorization: AccordLockTaskAuthorization = {
      ...expiredAuthorization,
      authorization_id: '55555555-5555-4555-8555-555555555555',
      task_id: '66666666-6666-4666-8666-666666666666',
      authorization_digest: `sha256:${'f'.repeat(64)}`,
      prepared_at: now,
      expires_at: now + 8 * 60 * 60,
    };
    const bridge = createBridge({
      getPendingTaskAuthorizations: vi
        .fn()
        .mockResolvedValueOnce([])
        .mockResolvedValue([rotatedAuthorization]),
      requestTaskAuthorization: vi.fn().mockResolvedValue(expiredAuthorization),
    });
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: {
            sessionId,
            initialMessage: { msg: expiredAuthorization.objective, images: [] },
          },
        })
      );
    });

    await waitFor(() => expect(bridge.getPendingTaskAuthorizations).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(bridge.submitTaskAuthorizationDecision).toHaveBeenCalledWith(
        expect.objectContaining({
          authorization_id: rotatedAuthorization.authorization_id,
          decision: 'APPROVE',
        })
      )
    );
    expect(getAccordLockTaskAuthorization(sessionId)).toBe('PENDING');
  });

  it('does not downgrade a still-valid approved session when session creation replays', async () => {
    const sessionId = 'session-duplicate';
    setAccordLockTaskAuthorization(sessionId, 'APPROVED', Math.floor(Date.now() / 1_000) + 60);
    const bridge = createBridge();
    render(
      <IntlTestWrapper>
        <TaskAuthorizationController bridge={bridge} />
      </IntlTestWrapper>
    );

    act(() => {
      window.dispatchEvent(
        new CustomEvent(AppEvents.ADD_ACTIVE_SESSION, {
          detail: { sessionId, initialMessage: { msg: authorization.objective, images: [] } },
        })
      );
    });

    await waitFor(() => expect(bridge.getPendingTaskAuthorizations).toHaveBeenCalledOnce());
    expect(bridge.requestTaskAuthorization).not.toHaveBeenCalled();
    expect(bridge.submitTaskAuthorizationDecision).not.toHaveBeenCalled();
    expect(getAccordLockTaskAuthorization(sessionId)).toBe('APPROVED');
  });
});
