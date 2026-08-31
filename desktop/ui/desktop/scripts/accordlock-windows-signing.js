const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const WINDOWS_PE_EXTENSIONS = new Set(['.dll', '.efi', '.exe', '.node', '.scr', '.sys']);
const SIDECAR_SPECS = Object.freeze([
  Object.freeze({
    binary: 'goose.exe',
    marker: 'accordlock-build.json',
    expectedKeys: Object.freeze([
      'binary',
      'binary_sha256',
      'distribution',
      'policy_feature',
      'schema_version',
      'source_commit',
      'source_dirty',
    ]),
    validate(marker) {
      return (
        marker.schema_version === 2 &&
        marker.distribution === 'AccordLock' &&
        marker.policy_feature === 'accordlock-distribution'
      );
    },
  }),
  Object.freeze({
    binary: 'accordlock-agent-runtime.exe',
    marker: 'accordlock-runtime-build.json',
    expectedKeys: Object.freeze([
      'binary',
      'binary_sha256',
      'component',
      'distribution',
      'protocol_version',
      'schema_version',
      'source_commit',
      'source_dirty',
    ]),
    validate(marker) {
      return (
        marker.schema_version === 2 &&
        marker.distribution === 'AccordLock' &&
        marker.component === 'accordlock-agent-runtime' &&
        marker.protocol_version === 2
      );
    },
  }),
  Object.freeze({
    binary: 'accordlock-preflight-runner.exe',
    marker: 'accordlock-preflight-runner-build.json',
    expectedKeys: Object.freeze([
      'binary_sha256',
      'component',
      'dirty',
      'protocol_version',
      'schema_version',
      'source_commit',
    ]),
    validate(marker) {
      return (
        marker.schema_version === 1 &&
        marker.component === 'accordlock-preflight-runner' &&
        marker.protocol_version === 1
      );
    },
    sourceCommitPattern: /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u,
    dirtyKey: 'dirty',
    digestPrefix: 'sha256:',
    markerDoesNotNameBinary: true,
  }),
]);

function fail(message) {
  throw new Error(`AccordLock Windows signing failed: ${message}`);
}

function assertRegularFile(filePath, label) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    fail(`${label} is missing`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be one regular non-link file`);
  }
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonObject(filePath, label) {
  assertRegularFile(filePath, label);
  let value;
  try {
    value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must contain one JSON object`);
  }
  return value;
}

function validateMarker(marker, spec, label) {
  const actualKeys = Object.keys(marker).sort();
  const expectedKeys = [...spec.expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    fail(`${label} contains missing or unexpected fields`);
  }
  if (
    !spec.validate(marker) ||
    (!spec.markerDoesNotNameBinary && marker.binary !== spec.binary)
  ) {
    fail(`${label} identifies an incompatible component`);
  }
  const sourceCommitPattern = spec.sourceCommitPattern || /^[0-9a-f]{40}$/u;
  if (typeof marker.source_commit !== 'string' || !sourceCommitPattern.test(marker.source_commit)) {
    fail(`${label} has no valid source commit`);
  }
  const dirtyKey = spec.dirtyKey || 'source_dirty';
  if (marker[dirtyKey] !== false) {
    fail(`${label} is not from clean release source`);
  }
  const digestPattern = spec.digestPrefix
    ? new RegExp(`^${spec.digestPrefix}[0-9a-f]{64}$`, 'u')
    : /^[0-9a-f]{64}$/u;
  if (typeof marker.binary_sha256 !== 'string' || !digestPattern.test(marker.binary_sha256)) {
    fail(`${label} has no valid binary digest`);
  }
}

function markerDigest(marker, spec) {
  return spec.digestPrefix
    ? marker.binary_sha256.slice(spec.digestPrefix.length)
    : marker.binary_sha256;
}

function markerWithDigest(marker, spec, digest) {
  return {
    ...marker,
    binary_sha256: spec.digestPrefix ? `${spec.digestPrefix}${digest}` : digest,
  };
}

function readVerifiedSidecars(binDirectory) {
  const result = [];
  for (const spec of SIDECAR_SPECS) {
    const markerPath = path.join(binDirectory, spec.marker);
    const binaryPath = path.join(binDirectory, spec.binary);
    const marker = readJsonObject(markerPath, spec.marker);
    validateMarker(marker, spec, spec.marker);
    assertRegularFile(binaryPath, spec.binary);
    const digest = sha256File(binaryPath);
    if (digest !== markerDigest(marker, spec)) {
      fail(`${spec.binary} does not match ${spec.marker}`);
    }
    result.push({ binaryPath, digest, marker, markerPath, spec });
  }
  return result;
}

function writeJsonAtomically(filePath, value) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    fs.renameSync(temporaryPath, filePath);
  } finally {
    if (fs.existsSync(temporaryPath)) {
      fs.unlinkSync(temporaryPath);
    }
  }
}

function normalizeSigningOptions(signingOptions) {
  if (!signingOptions || typeof signingOptions !== 'object') {
    fail('signing options are missing');
  }
  const { certificateFile, certificatePassword, timestampServer } = signingOptions;
  if (typeof certificateFile !== 'string' || certificateFile.trim().length === 0) {
    fail('the certificate file is missing');
  }
  assertRegularFile(certificateFile, 'the certificate file');
  if (typeof certificatePassword !== 'string' || certificatePassword.length === 0) {
    fail('the certificate password is missing');
  }
  let timestampUrl;
  try {
    timestampUrl = new URL(timestampServer);
  } catch {
    fail('the timestamp server is not a valid URL');
  }
  if (
    timestampUrl.protocol !== 'https:' ||
    timestampUrl.username ||
    timestampUrl.password ||
    timestampUrl.search ||
    timestampUrl.hash
  ) {
    fail('the timestamp server must be a credential-free HTTPS URL');
  }
  return {
    certificateFile: path.resolve(certificateFile),
    certificatePassword,
    hashes: ['sha256'],
    timestampServer: timestampUrl.toString(),
  };
}

function redactedErrorMessage(error, secret) {
  const raw = error instanceof Error ? error.message : String(error);
  return secret ? raw.split(secret).join('[REDACTED]') : raw;
}

async function invokeSigner(files, signingOptions, signer) {
  if (!Array.isArray(files) || files.length === 0) {
    fail('no Windows executable was selected for signing');
  }
  const normalizedOptions = normalizeSigningOptions(signingOptions);
  const effectiveSigner =
    signer ||
    (async (options) => {
      const { sign } = require('@electron/windows-sign');
      await sign(options);
    });
  try {
    await effectiveSigner({ ...normalizedOptions, files: [...files] });
  } catch (error) {
    fail(
      `the signing tool failed (${redactedErrorMessage(error, normalizedOptions.certificatePassword)})`
    );
  }
}

async function signStagedWindowsSidecars({ binDirectory, signingOptions, signer }) {
  const resolvedBinDirectory = path.resolve(binDirectory);
  const sidecarsBeforeSigning = readVerifiedSidecars(resolvedBinDirectory);
  await invokeSigner(
    sidecarsBeforeSigning.map(({ binaryPath }) => binaryPath),
    signingOptions,
    signer
  );

  const signedDigests = {};
  for (const sidecar of sidecarsBeforeSigning) {
    assertRegularFile(sidecar.binaryPath, sidecar.spec.binary);
    const signedDigest = sha256File(sidecar.binaryPath);
    const updatedMarker = markerWithDigest(sidecar.marker, sidecar.spec, signedDigest);
    writeJsonAtomically(sidecar.markerPath, updatedMarker);
    signedDigests[sidecar.spec.binary] = signedDigest;
  }

  // Re-read every marker/binary pair after marker replacement. Any
  // partial signing or marker-write failure remains fail-closed.
  readVerifiedSidecars(resolvedBinDirectory);
  return signedDigests;
}

function collectSignablePeFiles(rootDirectory, excludedPaths) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail(`packaged application contains a symbolic link: ${entryPath}`);
      }
      if (entry.isDirectory()) {
        visit(entryPath);
        continue;
      }
      if (!entry.isFile()) {
        fail(`packaged application contains a non-regular filesystem entry: ${entryPath}`);
      }
      if (
        WINDOWS_PE_EXTENSIONS.has(path.extname(entry.name).toLowerCase()) &&
        !excludedPaths.has(path.resolve(entryPath))
      ) {
        files.push(path.resolve(entryPath));
      }
    }
  };
  visit(rootDirectory);
  return files.sort((left, right) => left.localeCompare(right, 'en'));
}

function verifyPackagedSidecars(outputPath, sourceSidecars) {
  const packagedBinDirectory = path.join(outputPath, 'resources', 'bin');
  const packagedSidecars = readVerifiedSidecars(packagedBinDirectory);
  for (let index = 0; index < sourceSidecars.length; index += 1) {
    const source = sourceSidecars[index];
    const packaged = packagedSidecars[index];
    if (source.spec.binary !== packaged.spec.binary || source.digest !== packaged.digest) {
      fail(`${packaged.spec.binary} changed while it was copied into the packaged application`);
    }
  }
  return packagedSidecars;
}

async function signPackagedWindowsApplication({
  outputPaths,
  signingOptions,
  signer,
  sourceBinDirectory,
}) {
  if (!Array.isArray(outputPaths) || outputPaths.length === 0) {
    fail('Electron Forge returned no packaged application path');
  }
  const sourceSidecars = readVerifiedSidecars(path.resolve(sourceBinDirectory));
  const snapshots = [];
  const excludedPaths = new Set();
  const resolvedOutputPaths = outputPaths.map((outputPath) => path.resolve(outputPath));

  for (const outputPath of resolvedOutputPaths) {
    const outputStat = fs.lstatSync(outputPath);
    if (!outputStat.isDirectory() || outputStat.isSymbolicLink()) {
      fail(`the packaged application path is not a regular directory: ${outputPath}`);
    }
    const packagedSidecars = verifyPackagedSidecars(outputPath, sourceSidecars);
    for (const sidecar of packagedSidecars) {
      excludedPaths.add(path.resolve(sidecar.binaryPath));
      snapshots.push({ binaryPath: sidecar.binaryPath, digest: sidecar.digest });
    }
  }

  const signableFiles = resolvedOutputPaths.flatMap((outputPath) =>
    collectSignablePeFiles(outputPath, excludedPaths)
  );
  await invokeSigner(signableFiles, signingOptions, signer);

  for (const snapshot of snapshots) {
    assertRegularFile(snapshot.binaryPath, path.basename(snapshot.binaryPath));
    if (sha256File(snapshot.binaryPath) !== snapshot.digest) {
      fail(`${path.basename(snapshot.binaryPath)} changed during application signing`);
    }
  }
  for (const outputPath of resolvedOutputPaths) {
    verifyPackagedSidecars(outputPath, sourceSidecars);
  }

  return {
    sidecarDigests: Object.fromEntries(
      sourceSidecars.map((item) => [item.spec.binary, item.digest])
    ),
    signedFiles: signableFiles,
  };
}

module.exports = {
  SIDECAR_SPECS,
  WINDOWS_PE_EXTENSIONS,
  collectSignablePeFiles,
  readVerifiedSidecars,
  sha256File,
  signPackagedWindowsApplication,
  signStagedWindowsSidecars,
};
