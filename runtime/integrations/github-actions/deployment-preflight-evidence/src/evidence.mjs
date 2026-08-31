import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';

export const EVIDENCE_SCHEMA_VERSION = 1;
export const EVIDENCE_BUNDLE_TYPE =
  'ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE';
export const MAX_EVIDENCE_BYTES = 256 * 1024;
export const MAX_TRUST_RECORD_BYTES = 64 * 1024;

const BUILD_DOMAIN = Buffer.from('accordlock:v1:build-trust-record\0', 'utf8');
const ARTIFACT_DOMAIN = Buffer.from(
  'accordlock:v1:artifact-trust-record\0',
  'utf8',
);
const ED25519_PKCS8_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const COMMIT_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const OWNER_PATTERN = /^(?=.{1,39}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u;
const REPOSITORY_PATTERN = /^(?=.{1,100}$)[A-Za-z0-9._-]+$/u;
const ECR_REPOSITORY_PATTERN =
  /^(?=.{2,256}$)[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
const REGION_PATTERN = /^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]$/u;
const WORKFLOW_PATTERN =
  /^\.github\/workflows\/[A-Za-z0-9._/-]+\.(?:yml|yaml)$/u;
const CANONICAL_BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const COMMERCIAL_REGION_EXCLUSIONS = [
  'cn-',
  'us-gov-',
  'us-iso-',
  'us-isob-',
  'us-isof-',
  'eu-isoe-',
];

export class EvidenceInputError extends Error {
  constructor(field) {
    super(`Invalid ${field}`);
    this.name = 'EvidenceInputError';
    this.field = field;
  }
}

function fail(field) {
  throw new EvidenceInputError(field);
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireObject(value, field) {
  if (!isPlainObject(value)) fail(field);
  return value;
}

function requireExactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((entry, index) => entry !== wanted[index])
  ) {
    fail(field);
  }
}

function requireString(value, field, maximumBytes = 512) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    Buffer.byteLength(value, 'utf8') > maximumBytes ||
    /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value)
  ) {
    fail(field);
  }
  return value;
}

export function requireEnvironmentId(value) {
  const environmentId = requireString(value, 'environment-id', 36);
  if (!UUID_PATTERN.test(environmentId) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/u.test(environmentId)) {
    fail('environment-id');
  }
  return environmentId;
}

function requireOwner(value) {
  const owner = requireString(value, 'GitHub owner', 39);
  if (!OWNER_PATTERN.test(owner)) fail('GitHub owner');
  return owner;
}

function requireRepository(value) {
  const repository = requireString(value, 'GitHub repository', 100);
  if (
    !REPOSITORY_PATTERN.test(repository) ||
    repository === '.' ||
    repository === '..'
  ) {
    fail('GitHub repository');
  }
  return repository;
}

function requireWorkflowRef(value) {
  const workflowRef = requireString(value, 'workflow-ref', 256);
  if (
    !WORKFLOW_PATTERN.test(workflowRef) ||
    workflowRef.includes('\\') ||
    workflowRef
      .split('/')
      .some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    fail('workflow-ref');
  }
  return workflowRef;
}

function requireRegistryId(value) {
  const registryId = requireString(value, 'ECR registry ID', 12);
  if (!/^\d{12}$/u.test(registryId)) fail('ECR registry ID');
  return registryId;
}

function requireRegion(value) {
  const region = requireString(value, 'ECR region', 32);
  if (
    !REGION_PATTERN.test(region) ||
    COMMERCIAL_REGION_EXCLUSIONS.some((prefix) => region.startsWith(prefix))
  ) {
    fail('ECR region');
  }
  return region;
}

function requireEcrRepository(value) {
  const repository = requireString(value, 'ECR repository', 256);
  if (!ECR_REPOSITORY_PATTERN.test(repository)) fail('ECR repository');
  return repository;
}

function requireDigest(value, field) {
  const digest = requireString(value, field, 71);
  if (!DIGEST_PATTERN.test(digest) || /^sha256:0{64}$/u.test(digest)) fail(field);
  return digest;
}

function requireCommit(value) {
  const commit = requireString(value, 'commit SHA', 64);
  if (!COMMIT_PATTERN.test(commit)) fail('commit SHA');
  return commit;
}

function requireSafeInteger(value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail(field);
  }
  return value;
}

export function parsePositiveSafeInteger(value, field) {
  const text = requireString(value, field, 16);
  if (!/^[1-9][0-9]{0,15}$/u.test(text)) fail(field);
  const parsed = BigInt(text);
  if (parsed > MAX_SAFE_INTEGER) fail(field);
  return Number(parsed);
}

export function parseBoundedInteger(value, field, minimum, maximum) {
  const text = requireString(value, field, 10);
  if (!/^(?:0|[1-9][0-9]{0,9})$/u.test(text)) fail(field);
  return requireSafeInteger(Number(text), field, minimum, maximum);
}

export function parseBoolean(value, field) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  fail(field);
}

function decodeCanonicalBase64Url(value, bytes, field) {
  const encoded = requireString(value, field, 128);
  if (!CANONICAL_BASE64URL_PATTERN.test(encoded)) fail(field);
  const decoded = Buffer.from(encoded, 'base64url');
  if (decoded.length !== bytes || decoded.toString('base64url') !== encoded) {
    decoded.fill(0);
    fail(field);
  }
  return decoded;
}

function privateKeyFromSeed(seed) {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

function rawPublicKey(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (
    !Buffer.isBuffer(der) ||
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !timingSafeEqual(der.subarray(0, ED25519_SPKI_PREFIX.length), ED25519_SPKI_PREFIX)
  ) {
    if (Buffer.isBuffer(der)) der.fill(0);
    throw new Error('Ed25519 public key encoding is unavailable');
  }
  const raw = Buffer.from(der.subarray(ED25519_SPKI_PREFIX.length));
  der.fill(0);
  return raw;
}

function publicKeyObject(encodedPublicKey, field) {
  const raw = decodeCanonicalBase64Url(encodedPublicKey, 32, field);
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  raw.fill(0);
  try {
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } finally {
    der.fill(0);
  }
}

function domainHash(domain, encodedPayload) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(encodedPayload.length));
  try {
    return createHash('sha256')
      .update(domain)
      .update(length)
      .update(encodedPayload)
      .digest();
  } finally {
    length.fill(0);
  }
}

function encodeBounded(value, maximumBytes, field) {
  let json;
  try {
    json = JSON.stringify(value);
  } catch {
    fail(field);
  }
  const encoded = Buffer.from(json, 'utf8');
  if (encoded.length === 0 || encoded.length > maximumBytes) fail(field);
  return encoded;
}

function signRecord(domain, payload, privateKey) {
  const encoded = encodeBounded(payload, MAX_TRUST_RECORD_BYTES, 'trust record');
  const hash = domainHash(domain, encoded);
  try {
    return sign(null, hash, privateKey).toString('base64url');
  } finally {
    encoded.fill(0);
    hash.fill(0);
  }
}

function verifyRecord(domain, payload, signature, publicKey, field) {
  const encodedSignature = decodeCanonicalBase64Url(signature, 64, `${field} signature`);
  const encoded = encodeBounded(payload, MAX_TRUST_RECORD_BYTES, field);
  const hash = domainHash(domain, encoded);
  try {
    if (!verify(null, hash, publicKey, encodedSignature)) fail(`${field} signature`);
  } finally {
    encodedSignature.fill(0);
    encoded.fill(0);
    hash.fill(0);
  }
}

function publicKeyHash(encodedPublicKey) {
  const raw = decodeCanonicalBase64Url(encodedPublicKey, 32, 'authority public key');
  try {
    return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
  } finally {
    raw.fill(0);
  }
}

function authorityFromSeed(seed, keyId) {
  const privateKey = privateKeyFromSeed(seed);
  const rawPublic = rawPublicKey(privateKey);
  try {
    return {
      privateKey,
      authority: {
        algorithm: 'Ed25519',
        key_id: keyId,
        public_key: rawPublic.toString('base64url'),
      },
    };
  } finally {
    rawPublic.fill(0);
  }
}

function orderedBuildPayload(value) {
  return {
    schema_version: value.schema_version,
    key_id: value.key_id,
    repository: value.repository,
    workflow_ref: value.workflow_ref,
    run_id: value.run_id,
    commit_sha: value.commit_sha,
    input_manifest_root: value.input_manifest_root,
    output_digest: value.output_digest,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
  };
}

function orderedArtifactPayload(value) {
  return {
    schema_version: value.schema_version,
    key_id: value.key_id,
    registry_id: value.registry_id,
    region: value.region,
    repository_name: value.repository_name,
    image_digest: value.image_digest,
    source_repository: value.source_repository,
    commit_sha: value.commit_sha,
    source_run_id: value.source_run_id,
    signature_valid: value.signature_valid,
    quarantined: value.quarantined,
    issued_at: value.issued_at,
    expires_at: value.expires_at,
  };
}

function requireAuthority(value, field) {
  const authority = requireObject(value, field);
  requireExactKeys(authority, ['algorithm', 'key_id', 'public_key'], field);
  if (authority.algorithm !== 'Ed25519') fail(`${field} algorithm`);
  requireString(authority.key_id, `${field} key ID`, 255);
  const raw = decodeCanonicalBase64Url(authority.public_key, 32, `${field} public key`);
  raw.fill(0);
  return authority;
}

function requireBuildPayload(value) {
  const payload = requireObject(value, 'build record payload');
  requireExactKeys(
    payload,
    [
      'schema_version',
      'key_id',
      'repository',
      'workflow_ref',
      'run_id',
      'commit_sha',
      'input_manifest_root',
      'output_digest',
      'issued_at',
      'expires_at',
    ],
    'build record payload',
  );
  if (payload.schema_version !== 1) fail('build record schema version');
  requireString(payload.key_id, 'build record key ID', 255);
  requireString(payload.repository, 'build repository', 257);
  requireWorkflowRef(payload.workflow_ref);
  requireSafeInteger(payload.run_id, 'build run ID', 1);
  requireCommit(payload.commit_sha);
  requireDigest(payload.input_manifest_root, 'input manifest root');
  requireDigest(payload.output_digest, 'build output digest');
  requireSafeInteger(payload.issued_at, 'build issued timestamp');
  requireSafeInteger(payload.expires_at, 'build expiry timestamp');
  return payload;
}

function requireArtifactPayload(value) {
  const payload = requireObject(value, 'artifact record payload');
  requireExactKeys(
    payload,
    [
      'schema_version',
      'key_id',
      'registry_id',
      'region',
      'repository_name',
      'image_digest',
      'source_repository',
      'commit_sha',
      'source_run_id',
      'signature_valid',
      'quarantined',
      'issued_at',
      'expires_at',
    ],
    'artifact record payload',
  );
  if (payload.schema_version !== 1) fail('artifact record schema version');
  requireString(payload.key_id, 'artifact record key ID', 255);
  requireRegistryId(payload.registry_id);
  requireRegion(payload.region);
  requireEcrRepository(payload.repository_name);
  requireDigest(payload.image_digest, 'artifact image digest');
  requireString(payload.source_repository, 'artifact source repository', 257);
  requireCommit(payload.commit_sha);
  requireSafeInteger(payload.source_run_id, 'artifact source run ID', 1);
  if (typeof payload.signature_valid !== 'boolean') fail('artifact signature result');
  if (typeof payload.quarantined !== 'boolean') fail('artifact quarantine result');
  requireSafeInteger(payload.issued_at, 'artifact issued timestamp');
  requireSafeInteger(payload.expires_at, 'artifact expiry timestamp');
  return payload;
}

function requireSignedRecord(value, payloadValidator, field) {
  const record = requireObject(value, field);
  requireExactKeys(record, ['payload', 'signature'], field);
  const payload = payloadValidator(record.payload);
  const signature = requireString(record.signature, `${field} signature`, 86);
  const raw = decodeCanonicalBase64Url(signature, 64, `${field} signature`);
  raw.fill(0);
  return { record, payload };
}

function assertValidity(label, issuedAt, expiresAt, nowSeconds) {
  if (expiresAt <= issuedAt || nowSeconds < issuedAt || nowSeconds >= expiresAt) {
    fail(`${label} validity window`);
  }
}

export function createAuthoritySetup(environmentId, entropy = randomBytes) {
  const canonicalEnvironmentId = requireEnvironmentId(environmentId);
  const buildSeed = entropy(32);
  const artifactSeed = entropy(32);
  if (
    !Buffer.isBuffer(buildSeed) ||
    !Buffer.isBuffer(artifactSeed) ||
    buildSeed.length !== 32 ||
    artifactSeed.length !== 32 ||
    timingSafeEqual(buildSeed, artifactSeed)
  ) {
    if (Buffer.isBuffer(buildSeed)) buildSeed.fill(0);
    if (Buffer.isBuffer(artifactSeed)) artifactSeed.fill(0);
    throw new Error('Secure authority generation failed');
  }
  try {
    const build = authorityFromSeed(buildSeed, `build-${canonicalEnvironmentId}`);
    const artifact = authorityFromSeed(
      artifactSeed,
      `artifact-${canonicalEnvironmentId}`,
    );
    return {
      schema_version: 1,
      environment_id: canonicalEnvironmentId,
      github_secrets: {
        ACCORDLOCK_BUILD_AUTHORITY_SEED: buildSeed.toString('base64url'),
        ACCORDLOCK_ARTIFACT_AUTHORITY_SEED: artifactSeed.toString('base64url'),
      },
      enrollment: {
        build: {
          ...build.authority,
          public_key_hash: publicKeyHash(build.authority.public_key),
        },
        artifact: {
          ...artifact.authority,
          public_key_hash: publicKeyHash(artifact.authority.public_key),
        },
      },
    };
  } finally {
    buildSeed.fill(0);
    artifactSeed.fill(0);
  }
}

export function buildEvidencePackage(input) {
  const value = requireObject(input, 'evidence input');
  requireExactKeys(
    value,
    [
      'environmentId',
      'githubOwner',
      'githubRepository',
      'workflowRef',
      'runId',
      'commitSha',
      'registryId',
      'region',
      'ecrRepository',
      'imageDigest',
      'inputManifestRoot',
      'artifactSignatureValid',
      'artifactQuarantined',
      'issuedAt',
      'expiresAt',
      'buildAuthoritySeed',
      'artifactAuthoritySeed',
    ],
    'evidence input',
  );
  const environmentId = requireEnvironmentId(value.environmentId);
  const githubOwner = requireOwner(value.githubOwner);
  const githubRepository = requireRepository(value.githubRepository);
  const workflowRef = requireWorkflowRef(value.workflowRef);
  const runId = requireSafeInteger(value.runId, 'run ID', 1);
  const commitSha = requireCommit(value.commitSha);
  const registryId = requireRegistryId(value.registryId);
  const region = requireRegion(value.region);
  const ecrRepository = requireEcrRepository(value.ecrRepository);
  const imageDigest = requireDigest(value.imageDigest, 'image digest');
  const inputManifestRoot = requireDigest(
    value.inputManifestRoot,
    'input manifest root',
  );
  if (typeof value.artifactSignatureValid !== 'boolean') {
    fail('artifact signature result');
  }
  if (typeof value.artifactQuarantined !== 'boolean') {
    fail('artifact quarantine result');
  }
  const issuedAt = requireSafeInteger(value.issuedAt, 'issued timestamp');
  const expiresAt = requireSafeInteger(value.expiresAt, 'expiry timestamp');
  if (expiresAt <= issuedAt) fail('validity window');
  const buildSeed = decodeCanonicalBase64Url(
    value.buildAuthoritySeed,
    32,
    'build authority seed',
  );
  const artifactSeed = decodeCanonicalBase64Url(
    value.artifactAuthoritySeed,
    32,
    'artifact authority seed',
  );
  try {
    if (timingSafeEqual(buildSeed, artifactSeed)) fail('authority separation');
    const buildKeyId = `build-${environmentId}`;
    const artifactKeyId = `artifact-${environmentId}`;
    const build = authorityFromSeed(buildSeed, buildKeyId);
    const artifact = authorityFromSeed(artifactSeed, artifactKeyId);
    const sourceRepository = `${githubOwner}/${githubRepository}`;
    const buildPayload = {
      schema_version: 1,
      key_id: buildKeyId,
      repository: sourceRepository,
      workflow_ref: workflowRef,
      run_id: runId,
      commit_sha: commitSha,
      input_manifest_root: inputManifestRoot,
      output_digest: imageDigest,
      issued_at: issuedAt,
      expires_at: expiresAt,
    };
    const artifactPayload = {
      schema_version: 1,
      key_id: artifactKeyId,
      registry_id: registryId,
      region,
      repository_name: ecrRepository,
      image_digest: imageDigest,
      source_repository: sourceRepository,
      commit_sha: commitSha,
      source_run_id: runId,
      signature_valid: value.artifactSignatureValid,
      quarantined: value.artifactQuarantined,
      issued_at: issuedAt,
      expires_at: expiresAt,
    };
    const evidence = {
      schema_version: EVIDENCE_SCHEMA_VERSION,
      bundle_type: EVIDENCE_BUNDLE_TYPE,
      environment_id: environmentId,
      github: {
        owner: githubOwner,
        repository: githubRepository,
        workflow_ref: workflowRef,
      },
      ecr: {
        registry_id: registryId,
        region,
        repository: ecrRepository,
      },
      build_authority: build.authority,
      artifact_authority: artifact.authority,
      build_record: {
        payload: buildPayload,
        signature: signRecord(BUILD_DOMAIN, buildPayload, build.privateKey),
      },
      artifact_record: {
        payload: artifactPayload,
        signature: signRecord(ARTIFACT_DOMAIN, artifactPayload, artifact.privateKey),
      },
    };
    verifyEvidencePackage(evidence, issuedAt);
    return evidence;
  } finally {
    buildSeed.fill(0);
    artifactSeed.fill(0);
  }
}

export function verifyEvidencePackage(value, nowSeconds = Math.floor(Date.now() / 1000)) {
  encodeBounded(value, MAX_EVIDENCE_BYTES, 'evidence package');
  const bundle = requireObject(value, 'evidence package');
  requireExactKeys(
    bundle,
    [
      'schema_version',
      'bundle_type',
      'environment_id',
      'github',
      'ecr',
      'build_authority',
      'artifact_authority',
      'build_record',
      'artifact_record',
    ],
    'evidence package',
  );
  if (bundle.schema_version !== EVIDENCE_SCHEMA_VERSION) fail('evidence schema version');
  if (bundle.bundle_type !== EVIDENCE_BUNDLE_TYPE) fail('evidence bundle type');
  const environmentId = requireEnvironmentId(bundle.environment_id);
  const github = requireObject(bundle.github, 'GitHub route');
  requireExactKeys(github, ['owner', 'repository', 'workflow_ref'], 'GitHub route');
  const owner = requireOwner(github.owner);
  const repository = requireRepository(github.repository);
  const workflowRef = requireWorkflowRef(github.workflow_ref);
  const ecr = requireObject(bundle.ecr, 'ECR route');
  requireExactKeys(ecr, ['registry_id', 'region', 'repository'], 'ECR route');
  const registryId = requireRegistryId(ecr.registry_id);
  const region = requireRegion(ecr.region);
  const ecrRepository = requireEcrRepository(ecr.repository);
  const buildAuthority = requireAuthority(bundle.build_authority, 'build authority');
  const artifactAuthority = requireAuthority(bundle.artifact_authority, 'artifact authority');
  const build = requireSignedRecord(
    bundle.build_record,
    requireBuildPayload,
    'build record',
  );
  const artifact = requireSignedRecord(
    bundle.artifact_record,
    requireArtifactPayload,
    'artifact record',
  );
  const now = requireSafeInteger(nowSeconds, 'verification timestamp');
  const sourceRepository = `${owner}/${repository}`;
  const buildKeyId = `build-${environmentId}`;
  const artifactKeyId = `artifact-${environmentId}`;
  if (
    buildAuthority.key_id !== buildKeyId ||
    build.payload.key_id !== buildKeyId ||
    artifactAuthority.key_id !== artifactKeyId ||
    artifact.payload.key_id !== artifactKeyId
  ) {
    fail('environment authority binding');
  }
  if (
    build.payload.repository !== sourceRepository ||
    build.payload.workflow_ref !== workflowRef ||
    artifact.payload.source_repository !== sourceRepository ||
    artifact.payload.registry_id !== registryId ||
    artifact.payload.region !== region ||
    artifact.payload.repository_name !== ecrRepository ||
    artifact.payload.source_run_id !== build.payload.run_id ||
    artifact.payload.commit_sha !== build.payload.commit_sha ||
    artifact.payload.image_digest !== build.payload.output_digest
  ) {
    fail('route and provenance binding');
  }
  assertValidity(
    'build record',
    build.payload.issued_at,
    build.payload.expires_at,
    now,
  );
  assertValidity(
    'artifact record',
    artifact.payload.issued_at,
    artifact.payload.expires_at,
    now,
  );
  const buildPublicKey = publicKeyObject(buildAuthority.public_key, 'build public key');
  const artifactPublicKey = publicKeyObject(
    artifactAuthority.public_key,
    'artifact public key',
  );
  verifyRecord(
    BUILD_DOMAIN,
    orderedBuildPayload(build.payload),
    build.record.signature,
    buildPublicKey,
    'build record',
  );
  verifyRecord(
    ARTIFACT_DOMAIN,
    orderedArtifactPayload(artifact.payload),
    artifact.record.signature,
    artifactPublicKey,
    'artifact record',
  );
  return bundle;
}

export function encodeEvidencePackage(value) {
  verifyEvidencePackage(value, value.build_record.payload.issued_at);
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (bytes.length > MAX_EVIDENCE_BYTES) fail('evidence package');
  return bytes;
}

export function evidenceDigest(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_EVIDENCE_BYTES) {
    fail('evidence bytes');
  }
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function publicAuthorityEnrollment(evidence) {
  const verified = verifyEvidencePackage(
    evidence,
    evidence.build_record.payload.issued_at,
  );
  return {
    environment_id: verified.environment_id,
    build: {
      ...verified.build_authority,
      public_key_hash: publicKeyHash(verified.build_authority.public_key),
    },
    artifact: {
      ...verified.artifact_authority,
      public_key_hash: publicKeyHash(verified.artifact_authority.public_key),
    },
  };
}
