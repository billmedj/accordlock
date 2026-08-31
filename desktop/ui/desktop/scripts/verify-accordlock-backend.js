const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const binDirectory = path.resolve(__dirname, '..', 'src', 'bin');
const markerPath = path.join(binDirectory, 'accordlock-build.json');
const uncommittedSourceSentinel = '0'.repeat(40);
const allowDirtyDevelopment =
  process.env.ACCORDLOCK_DEVELOPMENT_BUILD === '1' &&
  process.env.ACCORDLOCK_ALLOW_DIRTY_BUILD === '1';

function fail(message) {
  throw new Error(`AccordLock distribution verification failed: ${message}`);
}

if (!fs.existsSync(markerPath)) {
  fail('missing src/bin/accordlock-build.json; build the backend from this fork first');
}

let marker;
try {
  marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
} catch (error) {
  fail(`invalid build marker JSON (${error.message})`);
}

const expectedKeys = [
  'binary',
  'binary_sha256',
  'distribution',
  'policy_feature',
  'schema_version',
  'source_commit',
  'source_dirty',
];
const actualKeys = Object.keys(marker).sort();
if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
  fail(`unexpected build marker fields: ${actualKeys.join(', ')}`);
}
if (
  marker.schema_version !== 2 ||
  marker.distribution !== 'AccordLock' ||
  marker.policy_feature !== 'accordlock-distribution'
) {
  fail('backend was not identified as the protected AccordLock distribution');
}
if (typeof marker.source_commit !== 'string' || !/^[0-9a-f]{40}$/.test(marker.source_commit)) {
  fail('source commit is missing or malformed');
}
if (typeof marker.source_dirty !== 'boolean') {
  fail('source dirty state is missing or malformed');
}
if (marker.source_commit === uncommittedSourceSentinel && marker.source_dirty === false) {
  fail('an uncommitted source sentinel cannot identify a clean backend build');
}
if (marker.source_dirty !== false && !allowDirtyDevelopment) {
  fail('dirty backend source is allowed only for an explicit local development build');
}
if (
  typeof marker.binary !== 'string' ||
  marker.binary !== path.basename(marker.binary) ||
  marker.binary.length === 0
) {
  fail('backend binary name is invalid');
}
if (typeof marker.binary_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(marker.binary_sha256)) {
  fail('backend digest is missing or malformed');
}

const binaryPath = path.join(binDirectory, marker.binary);
if (!fs.existsSync(binaryPath) || !fs.statSync(binaryPath).isFile()) {
  fail(`declared backend binary is missing: ${marker.binary}`);
}
const actualDigest = crypto.createHash('sha256').update(fs.readFileSync(binaryPath)).digest('hex');
if (actualDigest !== marker.binary_sha256) {
  fail(`backend digest mismatch for ${marker.binary}`);
}

console.log(
  `Verified protected AccordLock backend ${marker.binary} at ${marker.source_commit.slice(0, 12)} (${actualDigest.slice(0, 12)}…)`
);

const runtimeMarkerPath = path.join(binDirectory, 'accordlock-runtime-build.json');
if (!fs.existsSync(runtimeMarkerPath)) {
  fail('missing src/bin/accordlock-runtime-build.json; stage the trusted runtime first');
}

let runtimeMarker;
try {
  runtimeMarker = JSON.parse(fs.readFileSync(runtimeMarkerPath, 'utf8'));
} catch (error) {
  fail(`invalid runtime build marker JSON (${error.message})`);
}

const expectedRuntimeKeys = [
  'binary',
  'binary_sha256',
  'component',
  'distribution',
  'protocol_version',
  'schema_version',
  'source_commit',
  'source_dirty',
];
const actualRuntimeKeys = Object.keys(runtimeMarker).sort();
if (JSON.stringify(actualRuntimeKeys) !== JSON.stringify(expectedRuntimeKeys)) {
  fail(`unexpected runtime build marker fields: ${actualRuntimeKeys.join(', ')}`);
}

const targetPlatform = process.env.ELECTRON_PLATFORM || process.platform;
const expectedRuntimeBinary =
  targetPlatform === 'win32' ? 'accordlock-agent-runtime.exe' : 'accordlock-agent-runtime';
if (
  runtimeMarker.schema_version !== 2 ||
  runtimeMarker.distribution !== 'AccordLock' ||
  runtimeMarker.component !== 'accordlock-agent-runtime' ||
  runtimeMarker.protocol_version !== 2
) {
  fail('runtime marker does not identify the AccordLock protocol v2 component');
}
if (
  typeof runtimeMarker.source_commit !== 'string' ||
  !/^[0-9a-f]{40}$/.test(runtimeMarker.source_commit)
) {
  fail('runtime source commit is missing or malformed');
}
if (typeof runtimeMarker.source_dirty !== 'boolean') {
  fail('runtime source dirty state is missing or malformed');
}
if (
  runtimeMarker.source_commit === uncommittedSourceSentinel &&
  runtimeMarker.source_dirty === false
) {
  fail('an uncommitted source sentinel cannot identify a clean runtime build');
}
if (runtimeMarker.source_dirty && !allowDirtyDevelopment) {
  fail('dirty runtime source is allowed only for an explicit local development build');
}
if (runtimeMarker.binary !== expectedRuntimeBinary) {
  fail(`runtime marker must declare the exact binary ${expectedRuntimeBinary}`);
}
if (
  typeof runtimeMarker.binary_sha256 !== 'string' ||
  !/^[0-9a-f]{64}$/.test(runtimeMarker.binary_sha256)
) {
  fail('runtime digest is missing or malformed');
}

const runtimeBinaryPath = path.join(binDirectory, expectedRuntimeBinary);
if (!fs.existsSync(runtimeBinaryPath) || !fs.statSync(runtimeBinaryPath).isFile()) {
  fail(`declared runtime binary is missing: ${expectedRuntimeBinary}`);
}
const actualRuntimeDigest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(runtimeBinaryPath))
  .digest('hex');
if (actualRuntimeDigest !== runtimeMarker.binary_sha256) {
  fail(`runtime digest mismatch for ${expectedRuntimeBinary}`);
}

console.log(
  `Verified AccordLock runtime ${expectedRuntimeBinary} at ${runtimeMarker.source_commit.slice(0, 12)} (${actualRuntimeDigest.slice(0, 12)}…)`
);

const preflightMarkerPath = path.join(binDirectory, 'accordlock-preflight-runner-build.json');
if (!fs.existsSync(preflightMarkerPath)) {
  fail(
    'missing src/bin/accordlock-preflight-runner-build.json; stage the deployment preflight runner first'
  );
}

let preflightMarker;
try {
  preflightMarker = JSON.parse(fs.readFileSync(preflightMarkerPath, 'utf8'));
} catch (error) {
  fail(`invalid deployment preflight runner marker JSON (${error.message})`);
}

const expectedPreflightKeys = [
  'binary_sha256',
  'component',
  'dirty',
  'protocol_version',
  'schema_version',
  'source_commit',
];
const actualPreflightKeys = Object.keys(preflightMarker).sort();
if (JSON.stringify(actualPreflightKeys) !== JSON.stringify(expectedPreflightKeys)) {
  fail(`unexpected deployment preflight runner marker fields: ${actualPreflightKeys.join(', ')}`);
}

const expectedPreflightBinary =
  targetPlatform === 'win32'
    ? 'accordlock-preflight-runner.exe'
    : 'accordlock-preflight-runner';
if (
  preflightMarker.schema_version !== 1 ||
  preflightMarker.component !== 'accordlock-preflight-runner' ||
  preflightMarker.protocol_version !== 1
) {
  fail('deployment preflight runner marker identifies an incompatible component');
}
if (
  typeof preflightMarker.source_commit !== 'string' ||
  !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(preflightMarker.source_commit)
) {
  fail('deployment preflight runner source commit is missing or malformed');
}
if (typeof preflightMarker.dirty !== 'boolean') {
  fail('deployment preflight runner dirty state is missing or malformed');
}
if (/^0+$/.test(preflightMarker.source_commit) && preflightMarker.dirty === false) {
  fail('an uncommitted source sentinel cannot identify a clean deployment preflight runner');
}
if (preflightMarker.dirty && !allowDirtyDevelopment) {
  fail('a dirty deployment preflight runner is allowed only for an explicit local development build');
}
if (
  typeof preflightMarker.binary_sha256 !== 'string' ||
  !/^sha256:[0-9a-f]{64}$/.test(preflightMarker.binary_sha256)
) {
  fail('deployment preflight runner digest is missing or malformed');
}
const preflightBinaryPath = path.join(binDirectory, expectedPreflightBinary);
if (!fs.existsSync(preflightBinaryPath) || !fs.statSync(preflightBinaryPath).isFile()) {
  fail(`declared deployment preflight runner is missing: ${expectedPreflightBinary}`);
}
const actualPreflightDigest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(preflightBinaryPath))
  .digest('hex');
if (`sha256:${actualPreflightDigest}` !== preflightMarker.binary_sha256) {
  fail(`deployment preflight runner digest mismatch for ${expectedPreflightBinary}`);
}

console.log(
  `Verified deployment preflight runner ${expectedPreflightBinary} at ${preflightMarker.source_commit.slice(0, 12)} (${actualPreflightDigest.slice(0, 12)}…)`
);
