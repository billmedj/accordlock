const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SIDECARS = Object.freeze([
  Object.freeze({
    binary: 'goose',
    marker: 'accordlock-build.json',
    digestField: 'binary_sha256',
  }),
  Object.freeze({
    binary: 'accordlock-agent-runtime',
    marker: 'accordlock-runtime-build.json',
    digestField: 'binary_sha256',
  }),
  Object.freeze({
    binary: 'accordlock-preflight-runner',
    marker: 'accordlock-preflight-runner-build.json',
    digestField: 'binary_sha256',
    digestPrefix: 'sha256:',
  }),
]);

function fail(message) {
  throw new Error(`AccordLock macOS sidecar verification failed: ${message}`);
}

function regularFile(filePath) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    fail(`${path.basename(filePath)} is missing (${error.message})`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${path.basename(filePath)} must be one regular non-link file`);
  }
}

function run(command, args, spawn = spawnSync) {
  const result = spawn(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) {
    const detail = `${result.stderr || ''}\n${result.stdout || ''}`.trim();
    fail(
      `${path.basename(command)} rejected ${path.basename(args.at(-1))}${detail ? ` (${detail})` : ''}`
    );
  }
  return `${result.stdout || ''}\n${result.stderr || ''}`;
}

function readMarker(markerPath) {
  regularFile(markerPath);
  let marker;
  try {
    marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
  } catch (error) {
    fail(`${path.basename(markerPath)} is not valid JSON (${error.message})`);
  }
  if (!marker || typeof marker !== 'object' || Array.isArray(marker)) {
    fail(`${path.basename(markerPath)} must contain one JSON object`);
  }
  return marker;
}

function verifyMacOSSidecars({
  binDirectory,
  expectedTeamId,
  expectedArchitecture,
  platform = process.platform,
  spawn = spawnSync,
}) {
  if (platform !== 'darwin') {
    fail('cryptographic verification must run on macOS');
  }
  if (!/^[A-Z0-9]{10}$/.test(expectedTeamId || '')) {
    fail('APPLE_TEAM_ID must be a 10-character uppercase Apple Team ID');
  }
  if (!['arm64', 'x64'].includes(expectedArchitecture)) {
    fail('the expected architecture must be arm64 or x64');
  }

  const resolvedBinDirectory = path.resolve(binDirectory);
  const expectedLipoArchitecture = expectedArchitecture === 'x64' ? 'x86_64' : 'arm64';
  const verified = [];

  for (const sidecar of SIDECARS) {
    const binaryPath = path.join(resolvedBinDirectory, sidecar.binary);
    const markerPath = path.join(resolvedBinDirectory, sidecar.marker);
    regularFile(binaryPath);
    const marker = readMarker(markerPath);
    const actualDigest = crypto
      .createHash('sha256')
      .update(fs.readFileSync(binaryPath))
      .digest('hex');
    const expectedDigest = `${sidecar.digestPrefix || ''}${actualDigest}`;
    if (marker[sidecar.digestField] !== expectedDigest) {
      fail(`${sidecar.marker} does not attest the signed ${sidecar.binary} bytes`);
    }

    run('/usr/bin/codesign', ['--verify', '--strict', '--verbose=2', binaryPath], spawn);
    const signature = run('/usr/bin/codesign', ['--display', '--verbose=4', binaryPath], spawn);
    const teamMatch = signature.match(/(?:^|\n)TeamIdentifier=([^\s]+)/u);
    if (!teamMatch || teamMatch[1] !== expectedTeamId) {
      fail(`${sidecar.binary} is not signed by Apple Team ${expectedTeamId}`);
    }
    if (!/(?:^|\n)Authority=Developer ID Application:/u.test(signature)) {
      fail(`${sidecar.binary} does not have a Developer ID Application signature`);
    }

    const architectures = run('/usr/bin/lipo', ['-archs', binaryPath], spawn).trim().split(/\s+/u);
    if (architectures.length !== 1 || architectures[0] !== expectedLipoArchitecture) {
      fail(`${sidecar.binary} must contain only the ${expectedLipoArchitecture} slice`);
    }
    verified.push(Object.freeze({ binary: sidecar.binary, sha256: actualDigest }));
  }

  return Object.freeze(verified);
}

if (require.main === module) {
  verifyMacOSSidecars({
    binDirectory:
      process.env.ACCORDLOCK_MACOS_BIN_DIRECTORY || path.resolve(__dirname, '..', 'src', 'bin'),
    expectedTeamId: process.env.APPLE_TEAM_ID,
    expectedArchitecture: process.env.ACCORDLOCK_MACOS_EXPECTED_ARCH,
  });
  console.log('Verified signed AccordLock macOS sidecars');
}

module.exports = { SIDECARS, verifyMacOSSidecars };
