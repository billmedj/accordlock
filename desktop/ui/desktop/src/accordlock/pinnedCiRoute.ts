import type { AccordLockEnvironmentProfileInput } from './environmentProfiles';

type PinnedCiRouteCurrent = Readonly<{
  runnerProfile: Readonly<{
    github: Readonly<{ repository: string; workflow: string }>;
    aws: Readonly<{ accountId: string; region: string; ecrRepository: string }>;
  }>;
}>;

export function assertPinnedCiRouteUnchanged(
  current: PinnedCiRouteCurrent,
  next: AccordLockEnvironmentProfileInput
): void {
  const profile = current.runnerProfile;
  const changed =
    profile.github.repository !== next.github.repository ||
    profile.github.workflow !== next.github.workflow ||
    profile.aws.accountId !== next.aws.accountId ||
    profile.aws.region !== next.aws.region ||
    profile.aws.ecrRepository !== next.aws.ecrRepository;
  if (changed) {
    throw new Error('Create a new environment to change the build route after trust is pinned.');
  }
}
