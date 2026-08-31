import { randomUUID } from 'node:crypto';

import type { DeploymentPreflightResultView } from '../components/accordlock/DeploymentPreflightResult';
import {
  deploymentPreflightInputSchema,
  prepareDeploymentPreflightRunnerRequest,
  type DeploymentPreflightInput,
  type DeploymentPreflightRunnerRequest,
} from './deploymentPreflight';
import {
  parseSignedDeploymentPreflightReceipt,
  projectDeploymentPreflightResult,
} from './deploymentPreflightReceipt';
import type {
  AccordLockEnvironmentProfileExecutionBundle,
  AccordLockEnvironmentVerificationFailureCode,
} from './environmentProfiles';
import {
  AccordLockEnvironmentProfileStore,
  type AccordLockTrustedEnvironmentVerification,
} from '../accordlockEnvironmentProfileStore';
import type {
  AppendVerifiedDeploymentPreflightReceiptInput,
  DeploymentPreflightReceiptArchiveSummary,
} from './deploymentPreflightReceiptArchive';

const DEFAULT_TIMEOUT_MILLISECONDS = 20_000;
const MAX_CLOCK_SKEW_SECONDS = 30;

export type AccordLockTrustedPreflightRunnerResponse = Readonly<{
  /** The trusted runner adapter sets this only after cryptographic signature verification. */
  signatureVerified: true;
  receipt: unknown;
  receiptPublicKey: string;
  receiptKeyId: string;
  verificationProfile: unknown;
}>;

export type AccordLockTrustedPreflightReceiptArchive = Readonly<{
  appendVerified(
    input: AppendVerifiedDeploymentPreflightReceiptInput
  ): Promise<DeploymentPreflightReceiptArchiveSummary>;
}>;

export type AccordLockTrustedPreflightRunner = Readonly<{
  /** Returns the exact digest produced by the Rust profile parser. */
  profileHash(
    bundle: AccordLockEnvironmentProfileExecutionBundle,
    signal: globalThis.AbortSignal
  ): Promise<string>;
  run(
    request: DeploymentPreflightRunnerRequest,
    bundle: AccordLockEnvironmentProfileExecutionBundle,
    signal: globalThis.AbortSignal
  ): Promise<AccordLockTrustedPreflightRunnerResponse>;
}>;

type ControllerOptions = {
  runner: AccordLockTrustedPreflightRunner | null;
  archive: AccordLockTrustedPreflightReceiptArchive;
  timeoutMilliseconds?: number;
  nowSeconds?: () => number;
};

class ControllerFailure extends Error {
  constructor(readonly code: AccordLockEnvironmentVerificationFailureCode) {
    super(code);
  }
}

function exactReceiptMatchesRequest(
  receipt: ReturnType<typeof parseSignedDeploymentPreflightReceipt>,
  request: DeploymentPreflightRunnerRequest,
  bundle: AccordLockEnvironmentProfileExecutionBundle,
  nowSeconds: number
): boolean {
  const payload = receipt.payload;
  const expectedClusterIdentity = `arn:aws:eks:${bundle.runnerProfile.aws.region}:${bundle.runnerProfile.aws.accountId}:cluster/${bundle.runnerProfile.kubernetes.clusterName}`;
  const expectedClusterEndpoint = bundle.runnerProfile.kubernetes.expectedEndpoint;
  const clusterBindingMatches =
    payload.outcome === 'INDETERMINATE'
      ? (payload.target.cluster_identity === expectedClusterIdentity ||
          payload.target.cluster_identity === 'unresolved') &&
        (payload.target.cluster_endpoint === expectedClusterEndpoint ||
          payload.target.cluster_endpoint === 'unresolved')
      : payload.target.cluster_identity === expectedClusterIdentity &&
        payload.target.cluster_endpoint === expectedClusterEndpoint;
  return (
    payload.check_id === request.check_id &&
    payload.environment_id === request.environment_id &&
    payload.environment_profile_hash === request.environment_profile_hash &&
    payload.candidate.repository === bundle.runnerProfile.github.repository &&
    payload.candidate.pull_number === request.pull_number &&
    payload.candidate.workflow_ref === bundle.runnerProfile.github.workflow &&
    payload.candidate.actions_run_id === request.actions_run_id &&
    payload.candidate.ecr_repository ===
      `${bundle.runnerProfile.aws.accountId}.dkr.ecr.${bundle.runnerProfile.aws.region}.amazonaws.com/${bundle.runnerProfile.aws.ecrRepository}` &&
    payload.candidate.image_digest === request.image_digest &&
    clusterBindingMatches &&
    payload.target.namespace === bundle.runnerProfile.kubernetes.namespace &&
    payload.target.deployment === bundle.runnerProfile.kubernetes.deployment &&
    payload.target.container === bundle.runnerProfile.kubernetes.container &&
    payload.started_at <= nowSeconds + MAX_CLOCK_SKEW_SECONDS &&
    payload.completed_at <= nowSeconds + MAX_CLOCK_SKEW_SECONDS &&
    (payload.outcome !== 'PASSED' ||
      (payload.valid_until != null && payload.valid_until > nowSeconds))
  );
}

async function recordAgainstCurrentProfile(
  store: AccordLockEnvironmentProfileStore,
  profileId: string,
  originalDigest: string,
  result: AccordLockTrustedEnvironmentVerification
) {
  try {
    return await store.recordVerification(profileId, originalDigest, result);
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes('changed during verification')) {
      throw error;
    }
    const current = await store.loadExecutionBundle(profileId);
    return store.recordVerification(profileId, current.runnerProfile.profile_digest, {
      status: 'FAILED',
      failureCode: 'PROFILE_CHANGED',
    });
  }
}

export class AccordLockEnvironmentProfilePreflightController {
  private readonly nowSeconds: () => number;
  private readonly runner: AccordLockTrustedPreflightRunner | null;
  private readonly archive: AccordLockTrustedPreflightReceiptArchive;
  private readonly timeoutMilliseconds: number;
  private readonly flights = new Map<
    string,
    Readonly<{ fingerprint: string; operation: Promise<DeploymentPreflightResultView> }>
  >();

  constructor(
    private readonly store: AccordLockEnvironmentProfileStore,
    options: ControllerOptions
  ) {
    const timeout = options.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS;
    if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > 60_000) {
      throw new Error('Environment preflight timeout is invalid');
    }
    this.runner = options.runner;
    this.archive = options.archive;
    this.timeoutMilliseconds = timeout;
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
  }

  run(rawInput: unknown): Promise<DeploymentPreflightResultView> {
    const input = deploymentPreflightInputSchema.parse(rawInput);
    const fingerprint = [
      input.protocol,
      input.schemaVersion,
      input.pullRequestUrl,
      input.buildRunUrl,
      input.imageDigest,
    ].join('\n');
    const existing = this.flights.get(input.profileId);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        return Promise.reject(
          new Error('A different deployment preflight is already running for this environment')
        );
      }
      return existing.operation;
    }

    const operation = this.runOnce(input);
    this.flights.set(input.profileId, { fingerprint, operation });
    const release = () => {
      if (this.flights.get(input.profileId)?.operation === operation) {
        this.flights.delete(input.profileId);
      }
    };
    void operation.then(release, release);
    return operation;
  }

  private async runOnce(input: DeploymentPreflightInput): Promise<DeploymentPreflightResultView> {
    const bundle = await this.store.loadExecutionBundle(input.profileId);
    const versionGuard = bundle.runnerProfile.profile_digest;

    try {
      if (!this.runner) throw new ControllerFailure('RUNNER_UNAVAILABLE');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMilliseconds);
      if (typeof timer.unref === 'function') timer.unref();
      let response: AccordLockTrustedPreflightRunnerResponse;
      let request: DeploymentPreflightRunnerRequest | undefined;
      try {
        const operation = (async () => {
          const authoritativeProfileHash = await this.runner!.profileHash(
            bundle,
            controller.signal
          );
          request = prepareDeploymentPreflightRunnerRequest({
            checkId: randomUUID(),
            environmentId: input.profileId,
            environmentProfileHash: authoritativeProfileHash,
            savedRepository: bundle.runnerProfile.github.repository,
            pullRequestUrl: input.pullRequestUrl,
            buildRunUrl: input.buildRunUrl,
            imageDigest: input.imageDigest,
          });
          return this.runner!.run(request, bundle, controller.signal);
        })();
        response = await Promise.race([
          operation,
          new Promise<never>((_resolve, reject) => {
            controller.signal.addEventListener(
              'abort',
              () => reject(new ControllerFailure('RUNNER_TIMEOUT')),
              { once: true }
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      if (!response || response.signatureVerified !== true) {
        throw new ControllerFailure('ATTESTATION_MISMATCH');
      }
      if (!request) throw new ControllerFailure('ATTESTATION_MISMATCH');
      let receipt: ReturnType<typeof parseSignedDeploymentPreflightReceipt>;
      try {
        receipt = parseSignedDeploymentPreflightReceipt(response.receipt);
      } catch {
        throw new ControllerFailure('ATTESTATION_MISMATCH');
      }
      const now = this.nowSeconds();
      if (
        !Number.isSafeInteger(now) ||
        now < 0 ||
        !exactReceiptMatchesRequest(receipt, request, bundle, now)
      ) {
        throw new ControllerFailure('ATTESTATION_MISMATCH');
      }

      await this.archive.appendVerified({
        signatureVerified: true,
        receipt: response.receipt,
        receiptPublicKey: response.receiptPublicKey,
        receiptKeyId: response.receiptKeyId,
        verificationProfile: response.verificationProfile,
      });

      const result = projectDeploymentPreflightResult(receipt);
      const verification: AccordLockTrustedEnvironmentVerification =
        receipt.payload.outcome === 'PASSED'
          ? { status: 'VERIFIED' }
          : {
              status: 'FAILED',
              failureCode:
                receipt.payload.outcome === 'BLOCKED'
                  ? 'PREFLIGHT_BLOCKED'
                  : 'PREFLIGHT_INDETERMINATE',
            };
      await recordAgainstCurrentProfile(this.store, input.profileId, versionGuard, verification);
      return result;
    } catch (error) {
      if (
        error instanceof ControllerFailure ||
        !(error instanceof Error) ||
        !error.message.includes('changed during verification')
      ) {
        const failureCode =
          error instanceof ControllerFailure ? error.code : ('RUNNER_REJECTED' as const);
        await recordAgainstCurrentProfile(this.store, input.profileId, versionGuard, {
          status: 'FAILED',
          failureCode,
        });
      }
      throw new Error('Deployment preflight could not be verified');
    }
  }
}
