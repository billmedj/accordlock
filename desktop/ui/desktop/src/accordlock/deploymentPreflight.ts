import { z } from 'zod';

export const ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL =
  'accordlock.deployment-preflight.v1' as const;

const profileId = z.string().uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const positiveInteger = z.number().int().positive().safe();

export const deploymentPreflightInputSchema = z
  .object({
    protocol: z.literal(ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL),
    schemaVersion: z.literal(1),
    profileId,
    pullRequestUrl: z.string().min(1).max(2_048),
    buildRunUrl: z.string().min(1).max(2_048),
    imageDigest: digest,
  })
  .strict();

export const deploymentPreflightRunnerRequestSchema = z
  .object({
    schema_version: z.literal(2),
    kind: z.literal('RUN_DEPLOYMENT_PREFLIGHT'),
    check_id: z.string().uuid(),
    environment_id: profileId,
    environment_profile_hash: digest,
    pull_number: positiveInteger,
    actions_run_id: positiveInteger,
    image_digest: digest,
  })
  .strict();

export type DeploymentPreflightInput = z.infer<typeof deploymentPreflightInputSchema>;
export type DeploymentPreflightRunnerRequest = z.infer<
  typeof deploymentPreflightRunnerRequestSchema
>;

export type ParsedGitHubCandidateUrls = {
  pullNumber: number;
  actionsRunId: number;
};

function canonicalRepository(value: string): { owner: string; repository: string } {
  const parts = value.split('/');
  if (
    parts.length !== 2 ||
    parts.some(
      (part) =>
        !part ||
        part.length > 100 ||
        part === '.' ||
        part === '..' ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/u.test(part)
    )
  ) {
    throw new Error('The saved GitHub repository is invalid');
  }
  return { owner: parts[0], repository: parts[1] };
}

function strictGitHubUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Enter a complete GitHub URL');
  }
  if (
    url.protocol !== 'https:' ||
    url.hostname !== 'github.com' ||
    url.port ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('Use an unmodified github.com HTTPS URL');
  }
  return url;
}

function positiveSafeInteger(value: string, label: string): number {
  if (!/^[1-9][0-9]*$/u.test(value)) throw new Error(`${label} is invalid`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} is invalid`);
  return parsed;
}

function pathParts(url: URL): string[] {
  if (url.pathname.endsWith('/') || /%2f|%5c/iu.test(url.pathname)) {
    throw new Error('The GitHub URL path is invalid');
  }
  return url.pathname
    .split('/')
    .filter(Boolean)
    .map((part) => decodeURIComponent(part));
}

export function parseDeploymentPreflightCandidateUrls(
  savedRepository: string,
  pullRequestUrl: string,
  buildRunUrl: string
): ParsedGitHubCandidateUrls {
  const saved = canonicalRepository(savedRepository);
  const pull = pathParts(strictGitHubUrl(pullRequestUrl));
  const run = pathParts(strictGitHubUrl(buildRunUrl));

  if (
    pull.length !== 4 ||
    pull[0] !== saved.owner ||
    pull[1] !== saved.repository ||
    pull[2] !== 'pull'
  ) {
    throw new Error('The pull request must belong to the saved repository');
  }
  if (
    run.length !== 5 ||
    run[0] !== saved.owner ||
    run[1] !== saved.repository ||
    run[2] !== 'actions' ||
    run[3] !== 'runs'
  ) {
    throw new Error('The build run must belong to the saved repository');
  }

  return {
    pullNumber: positiveSafeInteger(pull[3], 'Pull request number'),
    actionsRunId: positiveSafeInteger(run[4], 'Build run identifier'),
  };
}

export function prepareDeploymentPreflightRunnerRequest({
  checkId,
  environmentId,
  environmentProfileHash,
  savedRepository,
  pullRequestUrl,
  buildRunUrl,
  imageDigest,
}: {
  checkId: string;
  environmentId: string;
  environmentProfileHash: string;
  savedRepository: string;
  pullRequestUrl: string;
  buildRunUrl: string;
  imageDigest: string;
}): DeploymentPreflightRunnerRequest {
  const candidate = parseDeploymentPreflightCandidateUrls(
    savedRepository,
    pullRequestUrl,
    buildRunUrl
  );
  return deploymentPreflightRunnerRequestSchema.parse({
    schema_version: 2,
    kind: 'RUN_DEPLOYMENT_PREFLIGHT',
    check_id: checkId,
    environment_id: environmentId,
    environment_profile_hash: environmentProfileHash,
    pull_number: candidate.pullNumber,
    actions_run_id: candidate.actionsRunId,
    image_digest: imageDigest,
  });
}
