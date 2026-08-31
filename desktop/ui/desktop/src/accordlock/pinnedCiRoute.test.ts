import { describe, expect, it } from 'vitest';
import type { AccordLockEnvironmentProfileInput } from './environmentProfiles';
import { assertPinnedCiRouteUnchanged } from './pinnedCiRoute';

const input = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Production',
  runner: { mode: 'LOCAL_BUNDLED' },
  github: { repository: 'owner/repo', workflow: 'release.yml' },
  aws: { accountId: '123456789012', region: 'eu-west-1', ecrRepository: 'api' },
  kubernetes: { clusterName: 'prod', namespace: 'prod', deployment: 'api', container: 'api' },
  credentials: {
    github: { reference: 'rotated', material: { mode: 'SET', value: 'new-token' } },
    aws: { reference: 'rotated', material: { mode: 'SET', value: 'new-key' } },
  },
} as const satisfies AccordLockEnvironmentProfileInput;

const current = {
  runnerProfile: {
    profile_id: input.id,
    profile_version: 1,
    runner: input.runner,
    github: input.github,
    aws: input.aws,
    kubernetes: { ...input.kubernetes, expectedEndpoint: 'https://cluster.example' },
    profile_digest: `sha256:${'a'.repeat(64)}`,
  },
  credentialMaterial: { github: 'old', aws: 'old' },
} as const;

describe('assertPinnedCiRouteUnchanged', () => {
  it('allows credential rotation and Kubernetes-only edits', () => {
    expect(() =>
      assertPinnedCiRouteUnchanged(current, {
        ...input,
        kubernetes: { ...input.kubernetes, namespace: 'next' },
      })
    ).not.toThrow();
  });

  it.each([
    { github: { ...input.github, repository: 'owner/other' } },
    { github: { ...input.github, workflow: 'other.yml' } },
    { aws: { ...input.aws, accountId: '999999999999' } },
    { aws: { ...input.aws, region: 'us-east-1' } },
    { aws: { ...input.aws, ecrRepository: 'other' } },
  ])('rejects a pinned build-route change', (change) => {
    expect(() => assertPinnedCiRouteUnchanged(current, { ...input, ...change })).toThrow(
      'Create a new environment to change the build route after trust is pinned.'
    );
  });
});
