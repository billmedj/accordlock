import { describe, expect, it } from 'vitest';
import {
  parseDeploymentPreflightCandidateUrls,
  prepareDeploymentPreflightRunnerRequest,
} from './deploymentPreflight';

const environmentId = '11111111-1111-4111-8111-111111111111';
const checkId = '22222222-2222-4222-8222-222222222222';
const profileHash = `sha256:${'1'.repeat(64)}`;
const imageDigest = `sha256:${'2'.repeat(64)}`;

describe('Deployment Preflight selectors', () => {
  it('reduces saved-repository GitHub URLs to credential-free numeric selectors', () => {
    expect(
      parseDeploymentPreflightCandidateUrls(
        'accordlock/product',
        'https://github.com/accordlock/product/pull/42',
        'https://github.com/accordlock/product/actions/runs/987654321'
      )
    ).toEqual({ pullNumber: 42, actionsRunId: 987654321 });
  });

  it.each([
    [
      'http://github.com/accordlock/product/pull/42',
      'https://github.com/accordlock/product/actions/runs/1',
    ],
    [
      'https://evil.example/accordlock/product/pull/42',
      'https://github.com/accordlock/product/actions/runs/1',
    ],
    [
      'https://github.com/other/product/pull/42',
      'https://github.com/accordlock/product/actions/runs/1',
    ],
    [
      'https://github.com/accordlock/product/pull/42?diff=split',
      'https://github.com/accordlock/product/actions/runs/1',
    ],
    [
      'https://github.com/accordlock/product/pull/42',
      'https://github.com/accordlock/other/actions/runs/1',
    ],
    [
      'https://github.com/accordlock/product/pull/42',
      'https://github.com/accordlock/product/actions/runs/0',
    ],
  ])('rejects a caller-selected or malformed route', (pullRequestUrl, buildRunUrl) => {
    expect(() =>
      parseDeploymentPreflightCandidateUrls('accordlock/product', pullRequestUrl, buildRunUrl)
    ).toThrow();
  });

  it('builds the exact runner request without forwarding URLs or hosts', () => {
    const request = prepareDeploymentPreflightRunnerRequest({
      checkId,
      environmentId,
      environmentProfileHash: profileHash,
      savedRepository: 'accordlock/product',
      pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
      buildRunUrl: 'https://github.com/accordlock/product/actions/runs/987654321',
      imageDigest,
    });

    expect(request).toEqual({
      schema_version: 2,
      kind: 'RUN_DEPLOYMENT_PREFLIGHT',
      check_id: checkId,
      environment_id: environmentId,
      environment_profile_hash: profileHash,
      pull_number: 42,
      actions_run_id: 987654321,
      image_digest: imageDigest,
    });
    expect(JSON.stringify(request)).not.toContain('github.com');
  });

  it('rejects mutable tags before a runner is invoked', () => {
    expect(() =>
      prepareDeploymentPreflightRunnerRequest({
        checkId,
        environmentId,
        environmentProfileHash: profileHash,
        savedRepository: 'accordlock/product',
        pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
        buildRunUrl: 'https://github.com/accordlock/product/actions/runs/1',
        imageDigest: 'latest',
      })
    ).toThrow();
  });
});
