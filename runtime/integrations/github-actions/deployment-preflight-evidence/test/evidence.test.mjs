import assert from 'node:assert/strict';
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  buildEvidencePackage,
  createAuthoritySetup,
  encodeEvidencePackage,
  evidenceDigest,
  publicAuthorityEnrollment,
  verifyEvidencePackage,
} from '../src/evidence.mjs';

const ENVIRONMENT_ID = '29caac27-a7e7-4c22-9c8e-d5fbc80c6f42';
const BUILD_SEED = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString(
  'base64url',
);
const ARTIFACT_SEED = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 32),
).toString('base64url');
const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const IMAGE_DIGEST = `sha256:${'a'.repeat(64)}`;
const MANIFEST_ROOT = `sha256:${'b'.repeat(64)}`;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function input(overrides = {}) {
  return {
    environmentId: ENVIRONMENT_ID,
    githubOwner: 'acme',
    githubRepository: 'payments',
    workflowRef: '.github/workflows/release.yml',
    runId: 9007199254740000,
    commitSha: COMMIT,
    registryId: '123456789012',
    region: 'eu-west-1',
    ecrRepository: 'payments/api',
    imageDigest: IMAGE_DIGEST,
    inputManifestRoot: MANIFEST_ROOT,
    artifactSignatureValid: true,
    artifactQuarantined: false,
    issuedAt: 2000000000,
    expiresAt: 2000003600,
    buildAuthoritySeed: BUILD_SEED,
    artifactAuthoritySeed: ARTIFACT_SEED,
    ...overrides,
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function independentlyVerify(domain, payload, publicKey, signature) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encoded.length));
  const hash = createHash('sha256')
    .update(Buffer.from(domain, 'utf8'))
    .update(length)
    .update(encoded)
    .digest();
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey, 'base64url')]),
    format: 'der',
    type: 'spki',
  });
  return {
    encoded: encoded.toString('utf8'),
    hash: hash.toString('hex'),
    valid: verifySignature(null, hash, key, Buffer.from(signature, 'base64url')),
  };
}

test('matches the locked Rust-compatible Ed25519 vectors', () => {
  const evidence = buildEvidencePackage(input());
  assert.equal(
    evidence.build_authority.public_key,
    'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  );
  assert.equal(
    evidence.artifact_authority.public_key,
    'Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc',
  );
  assert.equal(
    evidence.build_record.signature,
    'RiGu12aW8FBTv5y8EyatTe4KA3-0-5heuAU1fcJhg5kWDip_j5fy4mCryZTYxM4xMnFxqLXHTPnMupBjZMBGAQ',
  );
  assert.equal(
    evidence.artifact_record.signature,
    '_OC2slOCX0pXTLmiTa0jxR5z2y06Z-ArMn8dneDONQ0ysvhNr3-tC87mLS3EMgyBOdJOcklZpQ8H0Uct-F5BCA',
  );

  const build = independentlyVerify(
    'accordlock:v1:build-trust-record\0',
    evidence.build_record.payload,
    evidence.build_authority.public_key,
    evidence.build_record.signature,
  );
  const artifact = independentlyVerify(
    'accordlock:v1:artifact-trust-record\0',
    evidence.artifact_record.payload,
    evidence.artifact_authority.public_key,
    evidence.artifact_record.signature,
  );
  assert.equal(build.valid, true);
  assert.equal(artifact.valid, true);
  assert.equal(build.hash, 'cbe92c0306683531cb1bcd590fd7367a9328664ccc6e5ce854842ac21c6c2198');
  assert.equal(
    artifact.hash,
    '3af5e716f8464bf4425d406903d4b9704e0d27b764c49498e022bffb9bd8a2d9',
  );
  assert.equal(
    build.encoded,
    `{"schema_version":1,"key_id":"build-${ENVIRONMENT_ID}","repository":"acme/payments","workflow_ref":".github/workflows/release.yml","run_id":9007199254740000,"commit_sha":"${COMMIT}","input_manifest_root":"${MANIFEST_ROOT}","output_digest":"${IMAGE_DIGEST}","issued_at":2000000000,"expires_at":2000003600}`,
  );
  assert.equal(
    artifact.encoded,
    `{"schema_version":1,"key_id":"artifact-${ENVIRONMENT_ID}","registry_id":"123456789012","region":"eu-west-1","repository_name":"payments/api","image_digest":"${IMAGE_DIGEST}","source_repository":"acme/payments","commit_sha":"${COMMIT}","source_run_id":9007199254740000,"signature_valid":true,"quarantined":false,"issued_at":2000000000,"expires_at":2000003600}`,
  );

  const bytes = encodeEvidencePackage(evidence);
  assert.equal(bytes.length, 1826);
  assert.equal(
    evidenceDigest(bytes),
    'sha256:ba40344d80f13cb9a5f952449ae4d4f44a7eaa0da46d3f97d488ced13f07435f',
  );
});

test('rejects signed-field tampering and unknown fields', () => {
  const original = buildEvidencePackage(input());
  const tamperedCommit = clone(original);
  tamperedCommit.build_record.payload.commit_sha = 'f'.repeat(40);
  assert.throws(() => verifyEvidencePackage(tamperedCommit, 2000000001));

  const tamperedDigest = clone(original);
  tamperedDigest.artifact_record.payload.image_digest = `sha256:${'c'.repeat(64)}`;
  assert.throws(() => verifyEvidencePackage(tamperedDigest, 2000000001));

  const unknownField = clone(original);
  unknownField.build_record.payload.untrusted = true;
  assert.throws(() => verifyEvidencePackage(unknownField, 2000000001));
});

test('rejects noncanonical, unbounded, and ambiguous producer inputs', () => {
  assert.throws(() => buildEvidencePackage(input({ imageDigest: `sha256:${'0'.repeat(64)}` })));
  assert.throws(() => buildEvidencePackage(input({ workflowRef: '.github/workflows//release.yml' })));
  assert.throws(() =>
    buildEvidencePackage(input({ environmentId: '29caac27-a7e7-0c22-9c8e-d5fbc80c6f42' })),
  );
  assert.throws(() => buildEvidencePackage(input({ buildAuthoritySeed: ARTIFACT_SEED })));
  assert.throws(() => buildEvidencePackage(input({ runId: Number.MAX_SAFE_INTEGER + 1 })));
});

test('rejects cross-environment and cross-route substitution', () => {
  const original = buildEvidencePackage(input());
  const otherEnvironment = clone(original);
  otherEnvironment.environment_id = '62d84d7b-bb4b-4f62-9bfa-e83ca55cc4e1';
  assert.throws(() => verifyEvidencePackage(otherEnvironment, 2000000001));

  const rewrittenEnvironment = clone(original);
  rewrittenEnvironment.environment_id = '62d84d7b-bb4b-4f62-9bfa-e83ca55cc4e1';
  rewrittenEnvironment.build_authority.key_id = `build-${rewrittenEnvironment.environment_id}`;
  rewrittenEnvironment.artifact_authority.key_id = `artifact-${rewrittenEnvironment.environment_id}`;
  rewrittenEnvironment.build_record.payload.key_id =
    rewrittenEnvironment.build_authority.key_id;
  rewrittenEnvironment.artifact_record.payload.key_id =
    rewrittenEnvironment.artifact_authority.key_id;
  assert.throws(() => verifyEvidencePackage(rewrittenEnvironment, 2000000001));

  const otherRoute = clone(original);
  otherRoute.ecr.repository = 'payments/other';
  assert.throws(() => verifyEvidencePackage(otherRoute, 2000000001));
});

test('rejects records outside their signed validity window', () => {
  const evidence = buildEvidencePackage(input());
  assert.throws(() => verifyEvidencePackage(evidence, 1999999999));
  assert.throws(() => verifyEvidencePackage(evidence, 2000003600));
  assert.equal(verifyEvidencePackage(evidence, 2000003599), evidence);
});

test('exports public enrollment without either private seed', () => {
  const evidence = buildEvidencePackage(input());
  const enrollment = publicAuthorityEnrollment(evidence);
  const encoded = JSON.stringify(enrollment);
  assert.equal(enrollment.environment_id, ENVIRONMENT_ID);
  assert.equal(enrollment.build.key_id, `build-${ENVIRONMENT_ID}`);
  assert.match(enrollment.build.public_key_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.match(enrollment.artifact.public_key_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(encoded.includes(BUILD_SEED), false);
  assert.equal(encoded.includes(ARTIFACT_SEED), false);
});

test('authority setup uses independent entropy and returns one explicit setup object', () => {
  let sequence = 0;
  const setup = createAuthoritySetup(ENVIRONMENT_ID, (size) => {
    assert.equal(size, 32);
    const result = Buffer.alloc(32, sequence);
    sequence += 1;
    return result;
  });
  assert.equal(sequence, 2);
  assert.equal(
    setup.github_secrets.ACCORDLOCK_BUILD_AUTHORITY_SEED,
    Buffer.alloc(32, 0).toString('base64url'),
  );
  assert.equal(
    setup.github_secrets.ACCORDLOCK_ARTIFACT_AUTHORITY_SEED,
    Buffer.alloc(32, 1).toString('base64url'),
  );
  assert.equal(setup.enrollment.build.key_id, `build-${ENVIRONMENT_ID}`);
  assert.equal(setup.enrollment.artifact.key_id, `artifact-${ENVIRONMENT_ID}`);
  assert.notEqual(setup.enrollment.build.public_key, setup.enrollment.artifact.public_key);
});

test('setup CLI prints secrets only after the explicit local flag', () => {
  const script = path.resolve('src/setup-authorities.mjs');
  const refused = spawnSync(
    process.execPath,
    [script, '--environment-id', ENVIRONMENT_ID],
    { encoding: 'utf8', env: { ...process.env, CI: '', GITHUB_ACTIONS: '' } },
  );
  assert.notEqual(refused.status, 0);
  assert.equal(refused.stdout, '');
  assert.match(refused.stderr, /--show-secrets/u);

  const allowed = spawnSync(
    process.execPath,
    [script, '--environment-id', ENVIRONMENT_ID, '--show-secrets'],
    { encoding: 'utf8', env: { ...process.env, CI: '', GITHUB_ACTIONS: '' } },
  );
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.stderr, '');
  const parsed = JSON.parse(allowed.stdout);
  assert.equal(parsed.environment_id, ENVIRONMENT_ID);
  assert.match(
    parsed.github_secrets.ACCORDLOCK_BUILD_AUTHORITY_SEED,
    /^[A-Za-z0-9_-]{43}$/u,
  );
  assert.match(parsed.enrollment.build.public_key, /^[A-Za-z0-9_-]{43}$/u);
});

test('the action writes one bounded package and never logs authority seeds', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-evidence-'));
  try {
    const githubOutput = path.join(temporary, 'github-output.txt');
    fs.writeFileSync(githubOutput, '', { mode: 0o600 });
    const action = spawnSync(process.execPath, [path.resolve('src/action.mjs')], {
      cwd: temporary,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH ?? '',
        GITHUB_REPOSITORY: 'acme/payments',
        GITHUB_WORKFLOW_REF:
          'acme/payments/.github/workflows/release.yml@refs/heads/main',
        GITHUB_RUN_ID: '417',
        GITHUB_SHA: COMMIT,
        GITHUB_WORKSPACE: temporary,
        GITHUB_OUTPUT: githubOutput,
        'INPUT_ENVIRONMENT-ID': ENVIRONMENT_ID,
        'INPUT_WORKFLOW-REF': '.github/workflows/release.yml',
        'INPUT_ECR-REGISTRY-ID': '123456789012',
        'INPUT_ECR-REGION': 'eu-west-1',
        'INPUT_ECR-REPOSITORY': 'payments/api',
        'INPUT_IMAGE-DIGEST': IMAGE_DIGEST,
        'INPUT_INPUT-MANIFEST-ROOT': MANIFEST_ROOT,
        'INPUT_ARTIFACT-SIGNATURE-VALID': 'true',
        'INPUT_ARTIFACT-QUARANTINED': 'false',
        'INPUT_BUILD-AUTHORITY-SEED': BUILD_SEED,
        'INPUT_ARTIFACT-AUTHORITY-SEED': ARTIFACT_SEED,
        'INPUT_VALIDITY-SECONDS': '3600',
        'INPUT_OUTPUT-FILE': 'evidence.json',
      },
    });
    assert.equal(action.status, 0, action.stderr);
    assert.equal(action.stderr, '');
    assert.equal(action.stdout, 'AccordLock deployment evidence created.\n');
    const evidencePath = path.join(temporary, 'evidence.json');
    const packageBytes = fs.readFileSync(evidencePath);
    const evidence = JSON.parse(packageBytes.toString('utf8'));
    verifyEvidencePackage(evidence);
    assert.equal(evidence.build_record.payload.run_id, 417);
    const visible = `${action.stdout}${action.stderr}${fs.readFileSync(
      githubOutput,
      'utf8',
    )}${packageBytes.toString('utf8')}`;
    assert.equal(visible.includes(BUILD_SEED), false);
    assert.equal(visible.includes(ARTIFACT_SEED), false);
    assert.match(fs.readFileSync(githubOutput, 'utf8'), /evidence-sha256=sha256:[0-9a-f]{64}/u);
    assert.deepEqual(
      fs.readdirSync(temporary).sort(),
      ['evidence.json', 'github-output.txt'],
    );
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test('the action fails closed when the declared workflow is not the running workflow', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-evidence-'));
  try {
    const githubOutput = path.join(temporary, 'github-output.txt');
    fs.writeFileSync(githubOutput, '');
    const action = spawnSync(process.execPath, [path.resolve('src/action.mjs')], {
      cwd: temporary,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH ?? '',
        GITHUB_REPOSITORY: 'acme/payments',
        GITHUB_WORKFLOW_REF:
          'acme/payments/.github/workflows/other.yml@refs/heads/main',
        GITHUB_RUN_ID: '417',
        GITHUB_SHA: COMMIT,
        GITHUB_WORKSPACE: temporary,
        GITHUB_OUTPUT: githubOutput,
        'INPUT_WORKFLOW-REF': '.github/workflows/release.yml',
      },
    });
    assert.notEqual(action.status, 0);
    assert.equal(action.stdout, '');
    assert.equal(
      action.stderr,
      'AccordLock deployment evidence generation failed: invalid workflow identity.\n',
    );
    assert.deepEqual(fs.readdirSync(temporary), ['github-output.txt']);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
