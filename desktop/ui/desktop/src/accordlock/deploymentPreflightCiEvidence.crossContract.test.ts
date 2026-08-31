import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AccordLockDeploymentPreflightCiEvidenceImporter,
  verifyDeploymentPreflightCiEvidenceBundle,
} from './deploymentPreflightCiEvidence';

const execFileAsync = promisify(execFile);
const ENVIRONMENT_ID = '55555555-5555-4555-8555-555555555555';
const RUN_ID = 24_680;
const ISSUED_AT = 1_900_000_000;
const EXPIRES_AT = ISSUED_AT + 900;
const ACTION_MODULE_URL = pathToFileURL(
  path.resolve(
    process.cwd(),
    '../../../runtime/integrations/github-actions/deployment-preflight-evidence/src/evidence.mjs'
  )
);
const temporaryDirectories: string[] = [];

const ACTION_EMITTER_SCRIPT = `
const action = await import(process.argv[1]);
const input = JSON.parse(Buffer.from(process.argv[2], 'base64url').toString('utf8'));
process.stdout.write(JSON.stringify(action.buildEvidencePackage(input)));
`;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => fs.rm(directory, { recursive: true, force: true }))
  );
});

function digest(seed: string): string {
  return `sha256:${createHash('sha256').update(seed, 'utf8').digest('hex')}`;
}

async function emitEvidenceWithGitHubAction(): Promise<unknown> {
  const input = {
    environmentId: ENVIRONMENT_ID,
    githubOwner: 'accordlock',
    githubRepository: 'product',
    workflowRef: '.github/workflows/release.yml',
    runId: RUN_ID,
    commitSha: 'a'.repeat(40),
    registryId: '123456789012',
    region: 'eu-west-3',
    ecrRepository: 'product/api',
    imageDigest: digest('container-image'),
    inputManifestRoot: digest('source-manifest'),
    artifactSignatureValid: true,
    artifactQuarantined: false,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    buildAuthoritySeed: Buffer.alloc(32, 0x11).toString('base64url'),
    artifactAuthoritySeed: Buffer.alloc(32, 0x22).toString('base64url'),
  };
  const encodedInput = Buffer.from(JSON.stringify(input), 'utf8').toString('base64url');
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    ['--input-type=module', '--eval', ACTION_EMITTER_SCRIPT, ACTION_MODULE_URL.href, encodedInput],
    {
      encoding: 'utf8',
      maxBuffer: 512 * 1_024,
      windowsHide: true,
    }
  );
  if (stderr.length > 0) throw new Error(`GitHub Action evidence emitter failed: ${stderr}`);
  return JSON.parse(stdout) as unknown;
}

describe('Deployment Preflight CI evidence cross-contract', () => {
  it('accepts and imports the exact JSON emitted by the dependency-free GitHub Action', async () => {
    const emittedBundle = await emitEvidenceWithGitHubAction();
    const verified = verifyDeploymentPreflightCiEvidenceBundle(emittedBundle, {
      nowSeconds: ISSUED_AT,
    });

    expect(verified).toMatchObject({
      runId: RUN_ID,
      imageDigest: digest('container-image'),
      enrollment: {
        environmentId: ENVIRONMENT_ID,
        build: { keyId: `build-${ENVIRONMENT_ID}` },
        artifact: { keyId: `artifact-${ENVIRONMENT_ID}` },
      },
    });

    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-action-contract-'));
    temporaryDirectories.push(root);
    const importer = new AccordLockDeploymentPreflightCiEvidenceImporter({
      buildRecordsDirectory: path.join(root, 'build'),
      artifactRecordsDirectory: path.join(root, 'artifact'),
      nowSeconds: () => ISSUED_AT,
    });
    const imported = await importer.importBundle(emittedBundle);

    expect(imported).toMatchObject({
      environmentId: ENVIRONMENT_ID,
      runId: RUN_ID,
      imageDigest: digest('container-image'),
      enrollment: verified.enrollment,
    });
    expect(JSON.parse(await fs.readFile(imported.buildRecordPath, 'utf8'))).toEqual(
      verified.bundle.build_record
    );
    expect(JSON.parse(await fs.readFile(imported.artifactRecordPath, 'utf8'))).toEqual(
      verified.bundle.artifact_record
    );
  });
});
