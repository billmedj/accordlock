import { createHash } from 'node:crypto';
import path from 'node:path';

import type {
  AccordLockCiAuthorityEnrollment,
  AccordLockCiAuthorityStatus,
} from '../accordlockPreflightTrustStore';
import type { AccordLockEnvironmentProfileExecutionBundle } from './environmentProfiles';
import { isAccordLockEnvironmentProfileId } from './environmentProfiles';
import {
  verifyDeploymentPreflightCiEvidenceBundle,
  type DeploymentPreflightCiAuthorityEnrollment,
  type DeploymentPreflightCiEvidenceImportResult,
  type DeploymentPreflightCiEvidenceImporterOptions,
  type VerifiedDeploymentPreflightCiEvidence,
} from './deploymentPreflightCiEvidence';

const DEFAULT_TIMEOUT_MILLISECONDS = 30_000;
const MIN_TIMEOUT_MILLISECONDS = 100;
const MAX_TIMEOUT_MILLISECONDS = 120_000;

export type DeploymentPreflightCiEnrollmentPreview = Readonly<{
  title: 'Trust this CI provenance?';
  environmentId: string;
  repository: string;
  workflow: string;
  runId: number;
  commit: string;
  imageDigest: string;
  registry: string;
  buildAuthorityFingerprint: string;
  artifactAuthorityFingerprint: string;
  note: 'Future key changes require an explicit rotation.';
}>;

export type DeploymentPreflightCiEnrollmentResult =
  | Readonly<{
      status: 'CANCELED';
      environmentId: string;
    }>
  | Readonly<{
      status: 'ENROLLED';
      environmentId: string;
      repository: string;
      workflow: string;
      runId: number;
      commit: string;
      imageDigest: string;
      buildAuthorityFingerprint: string;
      artifactAuthorityFingerprint: string;
    }>;

export type DeploymentPreflightCiEnrollmentEnvironmentStore = Readonly<{
  loadExecutionBundle(environmentId: unknown): Promise<AccordLockEnvironmentProfileExecutionBundle>;
}>;

export type DeploymentPreflightCiEnrollmentTrustStore = Readonly<{
  getCiAuthorityStatus(environmentId: unknown): Promise<AccordLockCiAuthorityStatus>;
  enrollCiAuthorities(
    environmentId: unknown,
    enrollment: unknown
  ): Promise<AccordLockCiAuthorityStatus>;
}>;

export type DeploymentPreflightCiEvidenceImporter = Readonly<{
  importBundle(
    value: unknown,
    signal?: globalThis.AbortSignal
  ): Promise<DeploymentPreflightCiEvidenceImportResult>;
}>;

export type DeploymentPreflightCiEnrollmentControllerOptions = Readonly<{
  environmentStore: DeploymentPreflightCiEnrollmentEnvironmentStore;
  initializeEnvironmentTrust(environmentId: string, signal: globalThis.AbortSignal): Promise<void>;
  trustStore: DeploymentPreflightCiEnrollmentTrustStore;
  trustedStateRoot: string;
  importerFactory(
    options: DeploymentPreflightCiEvidenceImporterOptions
  ): DeploymentPreflightCiEvidenceImporter;
  confirm(preview: DeploymentPreflightCiEnrollmentPreview): Promise<boolean>;
  timeoutMilliseconds?: number;
  nowSeconds?: () => number;
}>;

type Flight = Readonly<{
  fingerprint: string;
  operation: Promise<DeploymentPreflightCiEnrollmentResult>;
}>;

export type DeploymentPreflightCiEnrollmentCallOptions = Readonly<{
  confirm?: DeploymentPreflightCiEnrollmentControllerOptions['confirm'];
}>;

function exactAuthoritiesMatch(
  status: AccordLockCiAuthorityStatus,
  enrollment: DeploymentPreflightCiAuthorityEnrollment
): boolean {
  return (
    status.status === 'ENROLLED' &&
    status.environmentId === enrollment.environmentId &&
    status.build.keyId === enrollment.build.keyId &&
    status.build.publicKey === enrollment.build.publicKey &&
    status.build.publicKeyHash === enrollment.build.publicKeyHash &&
    status.artifact.keyId === enrollment.artifact.keyId &&
    status.artifact.publicKey === enrollment.artifact.publicKey &&
    status.artifact.publicKeyHash === enrollment.artifact.publicKeyHash
  );
}

function enrollmentForTrustStore(
  enrollment: DeploymentPreflightCiAuthorityEnrollment
): AccordLockCiAuthorityEnrollment {
  return Object.freeze({
    environmentId: enrollment.environmentId,
    build: Object.freeze({ ...enrollment.build }),
    artifact: Object.freeze({ ...enrollment.artifact }),
  });
}

function assertBundleMatchesEnvironment(
  environmentId: string,
  evidence: VerifiedDeploymentPreflightCiEvidence,
  execution: AccordLockEnvironmentProfileExecutionBundle
): void {
  const profile = execution.runnerProfile;
  const repository = `${evidence.bundle.github.owner}/${evidence.bundle.github.repository}`;
  if (
    profile.profile_id !== environmentId ||
    evidence.bundle.environment_id !== environmentId ||
    profile.github.repository !== repository ||
    profile.github.workflow !== evidence.bundle.github.workflow_ref ||
    profile.aws.accountId !== evidence.bundle.ecr.registry_id ||
    profile.aws.region !== evidence.bundle.ecr.region ||
    profile.aws.ecrRepository !== evidence.bundle.ecr.repository
  ) {
    throw new Error('CI evidence does not match the selected environment');
  }
}

function assertNotAborted(signal: globalThis.AbortSignal): void {
  if (signal.aborted) throw new Error('CI evidence enrollment timed out');
}

function preview(
  evidence: VerifiedDeploymentPreflightCiEvidence
): DeploymentPreflightCiEnrollmentPreview {
  const bundle = evidence.bundle;
  return Object.freeze({
    title: 'Trust this CI provenance?',
    environmentId: bundle.environment_id,
    repository: `${bundle.github.owner}/${bundle.github.repository}`,
    workflow: bundle.github.workflow_ref,
    runId: bundle.build_record.payload.run_id,
    commit: bundle.build_record.payload.commit_sha,
    imageDigest: bundle.artifact_record.payload.image_digest,
    registry: `${bundle.ecr.registry_id}.dkr.ecr.${bundle.ecr.region}.amazonaws.com/${bundle.ecr.repository}`,
    buildAuthorityFingerprint: evidence.enrollment.build.publicKeyHash,
    artifactAuthorityFingerprint: evidence.enrollment.artifact.publicKeyHash,
    note: 'Future key changes require an explicit rotation.',
  });
}

export class AccordLockDeploymentPreflightCiEnrollmentController {
  private readonly confirm: DeploymentPreflightCiEnrollmentControllerOptions['confirm'];
  private readonly environmentStore: DeploymentPreflightCiEnrollmentEnvironmentStore;
  private readonly flights = new Map<string, Flight>();
  private readonly importerFactory: DeploymentPreflightCiEnrollmentControllerOptions['importerFactory'];
  private readonly initializeEnvironmentTrust: DeploymentPreflightCiEnrollmentControllerOptions['initializeEnvironmentTrust'];
  private readonly nowSeconds: () => number;
  private readonly timeoutMilliseconds: number;
  private readonly trustStore: DeploymentPreflightCiEnrollmentTrustStore;
  private readonly trustedStateRoot: string;

  constructor(options: DeploymentPreflightCiEnrollmentControllerOptions) {
    const timeout = options.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS;
    if (
      !Number.isSafeInteger(timeout) ||
      timeout < MIN_TIMEOUT_MILLISECONDS ||
      timeout > MAX_TIMEOUT_MILLISECONDS
    ) {
      throw new Error('CI evidence enrollment timeout is invalid');
    }
    if (
      typeof options.trustedStateRoot !== 'string' ||
      !path.isAbsolute(options.trustedStateRoot) ||
      options.trustedStateRoot.includes('\0')
    ) {
      throw new Error('Trusted CI evidence state root must be absolute');
    }
    this.environmentStore = options.environmentStore;
    this.initializeEnvironmentTrust = options.initializeEnvironmentTrust;
    this.trustStore = options.trustStore;
    this.trustedStateRoot = path.normalize(options.trustedStateRoot);
    this.importerFactory = options.importerFactory;
    this.confirm = options.confirm;
    this.timeoutMilliseconds = timeout;
    this.nowSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1_000));
  }

  importForEnvironment(
    environmentId: unknown,
    rawBundle: unknown,
    options: DeploymentPreflightCiEnrollmentCallOptions = {}
  ): Promise<DeploymentPreflightCiEnrollmentResult> {
    if (!isAccordLockEnvironmentProfileId(environmentId)) {
      return Promise.reject(new Error('Environment profile identifier is invalid'));
    }
    let evidence: VerifiedDeploymentPreflightCiEvidence;
    try {
      evidence = verifyDeploymentPreflightCiEvidenceBundle(rawBundle, {
        nowSeconds: this.nowSeconds(),
      });
    } catch {
      return Promise.reject(new Error('CI evidence package is invalid'));
    }
    const fingerprint = `sha256:${createHash('sha256')
      .update(JSON.stringify(evidence.bundle), 'utf8')
      .digest('hex')}`;
    const existing = this.flights.get(environmentId);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        return Promise.reject(
          new Error('Different CI evidence is already being reviewed for this environment')
        );
      }
      return existing.operation;
    }

    const operation = this.runWithTimeout(environmentId, evidence, options.confirm ?? this.confirm);
    this.flights.set(environmentId, { fingerprint, operation });
    const release = () => {
      if (this.flights.get(environmentId)?.operation === operation) {
        this.flights.delete(environmentId);
      }
    };
    void operation.then(release, release);
    return operation;
  }

  private async runWithTimeout(
    environmentId: string,
    evidence: VerifiedDeploymentPreflightCiEvidence,
    confirm: DeploymentPreflightCiEnrollmentControllerOptions['confirm']
  ): Promise<DeploymentPreflightCiEnrollmentResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMilliseconds);
    if (typeof timer.unref === 'function') timer.unref();
    try {
      return await Promise.race([
        this.runOnce(environmentId, evidence, controller.signal, confirm),
        new Promise<never>((_resolve, reject) => {
          controller.signal.addEventListener(
            'abort',
            () => reject(new Error('CI evidence enrollment timed out')),
            { once: true }
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async runOnce(
    environmentId: string,
    evidence: VerifiedDeploymentPreflightCiEvidence,
    signal: globalThis.AbortSignal,
    confirm: DeploymentPreflightCiEnrollmentControllerOptions['confirm']
  ): Promise<DeploymentPreflightCiEnrollmentResult> {
    const initial = await this.environmentStore.loadExecutionBundle(environmentId);
    assertNotAborted(signal);
    assertBundleMatchesEnvironment(environmentId, evidence, initial);
    const profileGuard = initial.runnerProfile.profile_digest;
    const publicPreview = preview(evidence);
    const confirmed = await confirm(publicPreview);
    assertNotAborted(signal);
    if (typeof confirmed !== 'boolean') {
      throw new Error('Trusted CI evidence confirmation returned an invalid decision');
    }
    if (!confirmed) return Object.freeze({ status: 'CANCELED', environmentId });

    await this.assertCurrentEnvironment(environmentId, evidence, profileGuard, signal);
    await this.initializeEnvironmentTrust(environmentId, signal);
    assertNotAborted(signal);
    const currentStatus = await this.trustStore.getCiAuthorityStatus(environmentId);
    assertNotAborted(signal);
    if (currentStatus.status === 'NOT_INITIALIZED') {
      throw new Error('Local receipt trust was not initialized');
    }
    if (
      currentStatus.status === 'ENROLLED' &&
      !exactAuthoritiesMatch(currentStatus, evidence.enrollment)
    ) {
      throw new Error('Different CI authorities are already enrolled');
    }

    await this.assertCurrentEnvironment(environmentId, evidence, profileGuard, signal);
    const environmentRoot = path.join(this.trustedStateRoot, 'environments', environmentId);
    const importer = this.importerFactory({
      buildRecordsDirectory: path.join(environmentRoot, 'build-trust'),
      artifactRecordsDirectory: path.join(environmentRoot, 'artifact-trust'),
      nowSeconds: this.nowSeconds,
    });
    await importer.importBundle(evidence.bundle, signal);
    assertNotAborted(signal);
    await this.assertCurrentEnvironment(environmentId, evidence, profileGuard, signal);
    const enrolled = await this.trustStore.enrollCiAuthorities(
      environmentId,
      enrollmentForTrustStore(evidence.enrollment)
    );
    assertNotAborted(signal);
    if (!exactAuthoritiesMatch(enrolled, evidence.enrollment)) {
      throw new Error('CI authority enrollment could not be verified');
    }
    await this.assertCurrentEnvironment(environmentId, evidence, profileGuard, signal);

    return Object.freeze({
      status: 'ENROLLED',
      environmentId,
      repository: publicPreview.repository,
      workflow: publicPreview.workflow,
      runId: publicPreview.runId,
      commit: publicPreview.commit,
      imageDigest: publicPreview.imageDigest,
      buildAuthorityFingerprint: publicPreview.buildAuthorityFingerprint,
      artifactAuthorityFingerprint: publicPreview.artifactAuthorityFingerprint,
    });
  }

  private async assertCurrentEnvironment(
    environmentId: string,
    evidence: VerifiedDeploymentPreflightCiEvidence,
    expectedProfileDigest: string,
    signal: globalThis.AbortSignal
  ): Promise<void> {
    assertNotAborted(signal);
    const current = await this.environmentStore.loadExecutionBundle(environmentId);
    assertNotAborted(signal);
    if (current.runnerProfile.profile_digest !== expectedProfileDigest) {
      throw new Error('Environment changed during CI evidence enrollment');
    }
    assertBundleMatchesEnvironment(environmentId, evidence, current);
  }
}
