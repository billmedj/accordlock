import fs from 'node:fs';
import path from 'node:path';

import {
  EvidenceInputError,
  buildEvidencePackage,
  encodeEvidencePackage,
  evidenceDigest,
  parseBoolean,
  parseBoundedInteger,
  parsePositiveSafeInteger,
} from './evidence.mjs';

class ActionConfigurationError extends Error {
  constructor(field) {
    super(`Invalid ${field}`);
    this.name = 'ActionConfigurationError';
    this.field = field;
  }
}

function configurationFailure(field) {
  throw new ActionConfigurationError(field);
}

function readEnvironment(name, maximumBytes = 512) {
  const value = process.env[name];
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > maximumBytes ||
    /[\u0000\r\n]/u.test(value)
  ) {
    configurationFailure(name);
  }
  return value;
}

function readInput(name, maximumBytes = 512) {
  return readEnvironment(`INPUT_${name.toUpperCase()}`, maximumBytes);
}

function readSecretInput(name) {
  const environmentName = `INPUT_${name.toUpperCase()}`;
  const value = readEnvironment(environmentName, 128);
  delete process.env[environmentName];
  return value;
}

function splitRepository(value) {
  const parts = value.split('/');
  if (parts.length !== 2) configurationFailure('GitHub repository');
  return { owner: parts[0], repository: parts[1] };
}

function validateWorkflowIdentity(repository, workflowRef) {
  const githubWorkflowRef = readEnvironment('GITHUB_WORKFLOW_REF', 768);
  if (!githubWorkflowRef.startsWith(`${repository}/${workflowRef}@`)) {
    configurationFailure('workflow identity');
  }
}

function outputFilename() {
  const value = readInput('OUTPUT-FILE', 128);
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.json$/u.test(value) ||
    path.basename(value) !== value
  ) {
    configurationFailure('output-file');
  }
  return value;
}

function writeNewFile(filePath, contents) {
  let handle;
  let created = false;
  try {
    handle = fs.openSync(filePath, 'wx', 0o600);
    created = true;
    fs.writeFileSync(handle, contents);
    fs.fsyncSync(handle);
  } catch (error) {
    if (handle !== undefined) fs.closeSync(handle);
    if (created) {
      try {
        fs.unlinkSync(filePath);
      } catch {
        // The file was created by this process; a later failure remains fatal.
      }
    }
    throw error;
  }
  fs.closeSync(handle);
}

function setOutputs(outputs) {
  const outputPath = readEnvironment('GITHUB_OUTPUT', 4096);
  const lines = Object.entries(outputs)
    .map(([name, value]) => `${name}=${value}\n`)
    .join('');
  fs.appendFileSync(outputPath, lines, { encoding: 'utf8' });
}

function run() {
  const githubRepository = readEnvironment('GITHUB_REPOSITORY', 141);
  const repository = splitRepository(githubRepository);
  const workflowRef = readInput('WORKFLOW-REF', 256);
  validateWorkflowIdentity(githubRepository, workflowRef);
  const now = Math.floor(Date.now() / 1000);
  const validitySeconds = parseBoundedInteger(
    readInput('VALIDITY-SECONDS', 10),
    'validity-seconds',
    60,
    86400,
  );
  const expiresAt = now + validitySeconds;
  if (!Number.isSafeInteger(expiresAt)) configurationFailure('validity window');
  const evidence = buildEvidencePackage({
    environmentId: readInput('ENVIRONMENT-ID', 36),
    githubOwner: repository.owner,
    githubRepository: repository.repository,
    workflowRef,
    runId: parsePositiveSafeInteger(
      readEnvironment('GITHUB_RUN_ID', 16),
      'GitHub run ID',
    ),
    commitSha: readEnvironment('GITHUB_SHA', 64),
    registryId: readInput('ECR-REGISTRY-ID', 12),
    region: readInput('ECR-REGION', 32),
    ecrRepository: readInput('ECR-REPOSITORY', 256),
    imageDigest: readInput('IMAGE-DIGEST', 71),
    inputManifestRoot: readInput('INPUT-MANIFEST-ROOT', 71),
    artifactSignatureValid: parseBoolean(
      readInput('ARTIFACT-SIGNATURE-VALID', 5),
      'artifact-signature-valid',
    ),
    artifactQuarantined: parseBoolean(
      readInput('ARTIFACT-QUARANTINED', 5),
      'artifact-quarantined',
    ),
    issuedAt: now,
    expiresAt,
    buildAuthoritySeed: readSecretInput('BUILD-AUTHORITY-SEED'),
    artifactAuthoritySeed: readSecretInput('ARTIFACT-AUTHORITY-SEED'),
  });
  const contents = encodeEvidencePackage(evidence);
  const workspace = path.resolve(readEnvironment('GITHUB_WORKSPACE', 4096));
  const workspaceStat = fs.lstatSync(workspace);
  if (!workspaceStat.isDirectory() || workspaceStat.isSymbolicLink()) {
    configurationFailure('GitHub workspace');
  }
  const evidencePath = path.join(workspace, outputFilename());
  writeNewFile(evidencePath, contents);
  setOutputs({
    'evidence-path': evidencePath,
    'evidence-sha256': evidenceDigest(contents),
    'run-id': String(evidence.build_record.payload.run_id),
    'image-digest': evidence.artifact_record.payload.image_digest,
  });
  process.stdout.write('AccordLock deployment evidence created.\n');
}

try {
  run();
} catch (error) {
  const field =
    error instanceof EvidenceInputError || error instanceof ActionConfigurationError
      ? `: invalid ${error.field}`
      : '';
  process.stderr.write(`AccordLock deployment evidence generation failed${field}.\n`);
  process.exitCode = 1;
}
