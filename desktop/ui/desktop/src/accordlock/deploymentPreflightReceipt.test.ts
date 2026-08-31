import { describe, expect, it } from 'vitest';
import {
  parseSignedDeploymentPreflightReceipt,
  projectDeploymentPreflightResult,
} from './deploymentPreflightReceipt';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const signature = 'A'.repeat(86);

function passedReceipt(): Record<string, unknown> {
  return {
    payload: {
      schema_version: 2,
      check_id: '11111111-1111-4111-8111-111111111111',
      request_id: '22222222-2222-4222-8222-222222222222',
      environment_id: '33333333-3333-4333-8333-333333333333',
      environment_profile_hash: digest('1'),
      runner_id: '44444444-4444-4444-8444-444444444444',
      runner_registration_hash: digest('2'),
      dispatch_hash: digest('3'),
      policy_decision_hash: digest('4'),
      outcome: 'PASSED',
      reason_codes: ['ALLOWED'],
      candidate: {
        repository: 'accordlock/product',
        pull_number: 42,
        commit_sha: 'a'.repeat(40),
        workflow_ref: 'release.yml',
        actions_run_id: 987,
        ecr_repository: '123456789012.dkr.ecr.eu-west-3.amazonaws.com/product',
        image_digest: digest('5'),
      },
      target: {
        cluster_identity: 'production',
        cluster_endpoint: 'https://cluster.example.com',
        cluster_ca_hash: digest('d'),
        namespace: 'payments',
        deployment: 'api',
        deployment_uid: '55555555-5555-4555-8555-555555555555',
        resource_version: '12345',
        container: 'api',
        observed_image_digest: digest('5'),
      },
      checks: [
        {
          kind: 'CODE_REVIEW',
          status: 'PASSED',
          summary: 'ignored by renderer',
          observed_at: 1_800_000_000,
          freshness_seconds: 60,
          evidence_reference: digest('6'),
        },
        {
          kind: 'BUILD',
          status: 'PASSED',
          summary: 'ignored by renderer',
          observed_at: 1_800_000_000,
          freshness_seconds: 60,
          evidence_reference: digest('7'),
        },
        {
          kind: 'IMAGE',
          status: 'PASSED',
          summary: 'ignored by renderer',
          observed_at: 1_800_000_000,
          freshness_seconds: 60,
          evidence_reference: digest('8'),
        },
        {
          kind: 'TARGET',
          status: 'PASSED',
          summary: 'ignored by renderer',
          observed_at: 1_800_000_000,
          freshness_seconds: 60,
          evidence_reference: digest('9'),
        },
      ],
      evidence_root: digest('a'),
      started_at: 1_800_000_000,
      completed_at: 1_800_000_001,
      valid_until: 1_800_000_060,
      effect: 'NONE',
      deployment_performed: false,
      evaluation_attestation: { attestation: {}, cose_sign1: 'AA' },
    },
    receipt_hash: digest('b'),
    signer_key_id: 'preflight-receipts-v1',
    receipt_public_key_hash: digest('c'),
    signature,
  };
}

describe('Deployment Preflight receipts', () => {
  it('accepts a complete zero-effect receipt and projects fixed user copy', () => {
    const receipt = parseSignedDeploymentPreflightReceipt(passedReceipt());
    const projected = projectDeploymentPreflightResult(receipt);

    expect(projected.outcome).toBe('PASSED');
    expect(projected.checks.map((check) => check.summary)).toEqual([
      'Approved commit matches',
      'Successful run matches the commit',
      'Signed digest matches the build',
      'Deployment state is unchanged',
    ]);
    expect(JSON.stringify(projected.checks)).not.toContain('ignored by renderer');
    expect(projected.receiptJson).toContain('ignored by renderer');
  });

  it.each([
    ['effect', 'DEPLOY'],
    ['deployment_performed', true],
  ])('rejects an effect-bearing payload field %s', (field, value) => {
    const receipt = passedReceipt();
    (receipt.payload as Record<string, unknown>)[field] = value;
    expect(() => parseSignedDeploymentPreflightReceipt(receipt)).toThrow();
  });

  it('rejects a malformed envelope digest', () => {
    expect(() =>
      parseSignedDeploymentPreflightReceipt({
        ...passedReceipt(),
        receipt_hash: digest('0').replace('0', 'z'),
      })
    ).toThrow();
  });

  it('rejects partial passes and missing determinate evidence', () => {
    const partial = passedReceipt();
    const payload = partial.payload as Record<string, unknown>;
    const checks = payload.checks as Array<Record<string, unknown>>;
    checks[3] = { ...checks[3], status: 'INDETERMINATE', reason_code: 'PROVIDER_UNAVAILABLE' };
    delete payload.evidence_root;

    expect(() => parseSignedDeploymentPreflightReceipt(partial)).toThrow();
  });

  it('allows an indeterminate receipt only when it says which check was indeterminate', () => {
    const receipt = passedReceipt();
    const payload = receipt.payload as Record<string, unknown>;
    payload.outcome = 'INDETERMINATE';
    payload.reason_codes = ['PROVIDER_UNAVAILABLE'];
    payload.checks = [
      {
        kind: 'CODE_REVIEW',
        status: 'INDETERMINATE',
        summary: 'Provider unavailable',
        reason_code: 'PROVIDER_UNAVAILABLE',
      },
      { kind: 'BUILD', status: 'INDETERMINATE', summary: 'Not checked' },
      { kind: 'IMAGE', status: 'INDETERMINATE', summary: 'Not checked' },
      { kind: 'TARGET', status: 'INDETERMINATE', summary: 'Not checked' },
    ];
    delete payload.policy_decision_hash;
    delete payload.evidence_root;
    delete payload.evaluation_attestation;
    delete payload.valid_until;

    const parsed = parseSignedDeploymentPreflightReceipt(receipt);
    expect(projectDeploymentPreflightResult(parsed).checks[0].summary).toBe(
      'The provider is unavailable'
    );
  });

  it('accepts the explicit nulls emitted by Rust for absent optional evidence', () => {
    const receipt = passedReceipt();
    const payload = receipt.payload as Record<string, unknown>;
    payload.outcome = 'INDETERMINATE';
    payload.reason_codes = ['PROVIDER_UNAVAILABLE'];
    payload.policy_decision_hash = null;
    payload.evidence_root = null;
    payload.evaluation_attestation = null;
    payload.valid_until = null;
    payload.checks = [
      {
        kind: 'CODE_REVIEW',
        status: 'INDETERMINATE',
        summary: 'Provider unavailable',
        reason_code: 'PROVIDER_UNAVAILABLE',
        observed_at: null,
        freshness_seconds: null,
        evidence_reference: null,
      },
      ...(['BUILD', 'IMAGE', 'TARGET'] as const).map((kind) => ({
        kind,
        status: 'INDETERMINATE',
        summary: 'Not checked',
        reason_code: null,
        observed_at: null,
        freshness_seconds: null,
        evidence_reference: null,
      })),
    ];

    const parsed = parseSignedDeploymentPreflightReceipt(receipt);
    const projected = projectDeploymentPreflightResult(parsed);
    expect(projected.validUntil).toBeNull();
    expect(projected.checks[0].reasonCode).toBe('PROVIDER_UNAVAILABLE');
    expect(projected.checks[1]).not.toHaveProperty('reasonCode');
  });
});
