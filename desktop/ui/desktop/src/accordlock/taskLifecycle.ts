import { revokeAccordLockTaskAuthorization } from './taskBridge';

type TaskRevoker = (sessionId: string) => Promise<unknown>;

export async function stopAndRevokeTask(
  sessionId: string,
  stopModel: () => void,
  revoke: TaskRevoker = revokeAccordLockTaskAuthorization
): Promise<void> {
  stopModel();
  await revoke(sessionId);
}
