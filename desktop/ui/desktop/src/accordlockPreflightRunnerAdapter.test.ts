import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  AccordLockEnvironmentProfileStore,
  type AccordLockEnvironmentProfileSafeStorage,
} from './accordlockEnvironmentProfileStore';
import {
  AccordLockBundledPreflightRunner,
  executeAccordLockPreflightProcess,
  type AccordLockPreflightProcessExecutor,
  type AccordLockPreflightProcessInvocation,
} from './accordlockPreflightRunnerAdapter';
import { AccordLockPreflightTrustStore } from './accordlockPreflightTrustStore';
import { prepareDeploymentPreflightRunnerRequest } from './accordlock/deploymentPreflight';

const directories: string[] = [];
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const digest = (character: string) => `sha256:${character.repeat(64)}`;

const safeStorage: AccordLockEnvironmentProfileSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (plaintext) => Buffer.from(plaintext, 'utf8').reverse(),
  decryptString: (ciphertext) => Buffer.from(ciphertext).reverse().toString('utf8'),
};

function installation() {
  const receiptSeed = Buffer.alloc(32, 19);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, receiptSeed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const receiptPublicKey = Buffer.from(publicDer).subarray(12);
  const receiptPublicKeyHash = `sha256:${createHash('sha256')
    .update(receiptPublicKey)
    .digest('hex')}`;
  return {
    public: {
      schema_version: 1,
      receipt_key_id: 'accordlock-receipt-fixture',
      receipt_public_key: receiptPublicKey.toString('base64url'),
      receipt_public_key_hash: receiptPublicKeyHash,
    },
    secret: {
      schema_version: 1,
      runner_master_seed: Buffer.alloc(32, 23).toString('base64url'),
      receipt_signing_seed: receiptSeed.toString('base64url'),
    },
  };
}

async function stageRunner(directory: string, contents = 'preflight runner') {
  const binary = path.join(directory, 'accordlock-preflight-runner.exe');
  await fs.mkdir(directory, { recursive: true });
  await fs.writeFile(binary, contents);
  const binarySha256 = `sha256:${createHash('sha256').update(contents).digest('hex')}`;
  await fs.writeFile(
    path.join(directory, 'accordlock-preflight-runner-build.json'),
    JSON.stringify({
      schema_version: 1,
      component: 'accordlock-preflight-runner',
      protocol_version: 1,
      binary_sha256: binarySha256,
      source_commit: 'a'.repeat(40),
      dirty: false,
    })
  );
  return { binary, binarySha256 };
}

async function environmentBundle(directory: string) {
  const profileStore = new AccordLockEnvironmentProfileStore({ directory, safeStorage });
  const saved = await profileStore.save(
    {
      id: null,
      name: 'Production',
      runner: { mode: 'LOCAL_BUNDLED' },
      github: {
        repository: 'accordlock/product',
        workflow: '.github/workflows/release.yml@refs/heads/main',
      },
      aws: { accountId: '123456789012', region: 'eu-west-3', ecrRepository: 'accordlock/app' },
      kubernetes: {
        clusterName: 'production',
        namespace: 'accordlock',
        deployment: 'desktop-api',
        container: 'api',
      },
      credentials: {
        github: {
          reference: 'github-app',
          material: { mode: 'SET', value: 'github-fixture-token' },
        },
        aws: {
          reference: 'aws-role',
          material: {
            mode: 'SET',
            value: JSON.stringify({
              access_key_id: 'AKIATESTACCESS',
              secret_access_key: 'test-secret-access-key-material',
              session_token: 'test-session-token',
            }),
          },
        },
      },
    },
    'https://api.production.eks.example.com'
  );
  return { saved, bundle: await profileStore.loadExecutionBundle(saved.id) };
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true }))
  );
});

describe('bundled deployment preflight runner adapter', () => {
  it('uses bounded inherited stdio and terminates a cancelled local process', async () => {
    const signal = new AbortController().signal;
    const success = await executeAccordLockPreflightProcess({
      executable: process.execPath,
      args: [
        '-e',
        "let value='';process.stdin.on('data',c=>value+=c);process.stdin.on('end',()=>process.stdout.write(value==='input'?'ok':'bad'))",
      ],
      stdin: Buffer.from('input'),
      maximumStdoutBytes: 16,
      maximumStderrBytes: 16,
      signal,
    });
    expect(success.stdout.toString('utf8')).toBe('ok');

    await expect(
      executeAccordLockPreflightProcess({
        executable: process.execPath,
        args: ['-e', "process.stdout.write('x'.repeat(64))"],
        maximumStdoutBytes: 8,
        maximumStderrBytes: 16,
        signal,
      })
    ).rejects.toThrow('exceeded its limit');

    const controller = new AbortController();
    const pending = executeAccordLockPreflightProcess({
      executable: process.execPath,
      args: ['-e', 'setInterval(()=>{},1000)'],
      maximumStdoutBytes: 16,
      maximumStderrBytes: 16,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 25);
    await expect(pending).rejects.toThrow('cancelled');
  });

  it('uses the Rust profile hash, protected credentials, and independent receipt verification', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-runner-adapter-'));
    directories.push(root);
    const bin = path.join(root, 'bin');
    const state = path.join(root, 'state');
    const profileStoreDirectory = path.join(root, 'profiles');
    const staged = await stageRunner(bin);
    const { saved, bundle } = await environmentBundle(profileStoreDirectory);
    const trustStore = new AccordLockPreflightTrustStore({ directory: state, safeStorage });
    const keys = installation();
    const invocations: Array<{
      args: readonly string[];
      stdin?: Buffer;
      profile?: Record<string, unknown>;
    }> = [];
    const executeProcess = vi.fn<AccordLockPreflightProcessExecutor>(
      async (invocation: AccordLockPreflightProcessInvocation) => {
        const snapshot: {
          args: readonly string[];
          stdin?: Buffer;
          profile?: Record<string, unknown>;
        } = {
          args: invocation.args,
          ...(invocation.stdin ? { stdin: Buffer.from(invocation.stdin) } : {}),
        };
        invocations.push(snapshot);
        const command = invocation.args[0];
        if (command === 'init-installation-stdio') {
          return {
            stdout: Buffer.from(
              JSON.stringify({ schema_version: 1, public: keys.public, secrets: keys.secret })
            ),
          };
        }
        if (command === 'discover-eks-stdio') {
          return {
            stdout: Buffer.from(
              JSON.stringify({
                schema_version: 1,
                cluster_arn: 'arn:aws:eks:eu-west-3:123456789012:cluster/production',
                endpoint: 'https://api.production.eks.example.com',
                cluster_ca_hash: digest('c'),
              })
            ),
          };
        }
        const profileIndex = invocation.args.indexOf('--profile');
        const profile = JSON.parse(
          await fs.readFile(invocation.args[profileIndex + 1], 'utf8')
        ) as Record<string, unknown>;
        snapshot.profile = profile;
        if (command === 'profile-hash') {
          return {
            stdout: Buffer.from(
              JSON.stringify({
                valid: true,
                environment_profile_hash: digest('9'),
                receipt_public_key_hash: keys.public.receipt_public_key_hash,
              })
            ),
          };
        }
        if (command === 'check-stdio') {
          return {
            stdout: Buffer.from(
              JSON.stringify({
                payload: { fixture: true },
                receipt_hash: digest('8'),
                signer_key_id: keys.public.receipt_key_id,
                receipt_public_key_hash: keys.public.receipt_public_key_hash,
                signature: 'A'.repeat(86),
              })
            ),
          };
        }
        if (command === 'verify') {
          const receipt = JSON.parse(invocation.stdin!.toString('utf8')) as Record<string, unknown>;
          return {
            stdout: Buffer.from(
              JSON.stringify({
                valid: true,
                receipt_hash: receipt.receipt_hash,
                receipt_public_key_hash: receipt.receipt_public_key_hash,
              })
            ),
          };
        }
        throw new Error('Unexpected fake runner command');
      }
    );
    const adapter = new AccordLockBundledPreflightRunner({
      binaryDirectory: bin,
      stateDirectory: state,
      trustStore,
      isPackaged: true,
      allowDirtyDevelopment: false,
      expectedBinarySha256: staged.binarySha256,
      expectedProtocolVersion: 1,
      platform: 'win32',
      executeProcess,
    });
    const signal = new AbortController().signal;
    await expect(
      adapter.discoverEks(
        {
          accountId: '123456789012',
          region: 'eu-west-3',
          clusterName: 'production',
          awsCredential: bundle.credentialMaterial.aws,
        },
        signal
      )
    ).resolves.toEqual({
      clusterArn: 'arn:aws:eks:eu-west-3:123456789012:cluster/production',
      endpoint: 'https://api.production.eks.example.com',
      clusterCaHash: digest('c'),
    });
    await adapter.initializeEnvironmentTrust(saved.id, signal);
    const ciKey = (seedByte: number, keyId: string) => {
      const privateKey = createPrivateKey({
        key: Buffer.concat([PKCS8_PREFIX, Buffer.alloc(32, seedByte)]),
        format: 'der',
        type: 'pkcs8',
      });
      const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
      const raw = Buffer.from(der).subarray(12);
      return {
        keyId,
        publicKey: raw.toString('base64url'),
        publicKeyHash: `sha256:${createHash('sha256').update(raw).digest('hex')}`,
      };
    };
    await trustStore.enrollCiAuthorities(saved.id, {
      environmentId: saved.id,
      build: ciKey(31, `build-${saved.id}`),
      artifact: ciKey(37, `artifact-${saved.id}`),
    });

    const authoritativeHash = await adapter.profileHash(bundle, signal);
    const request = prepareDeploymentPreflightRunnerRequest({
      checkId: '33333333-3333-4333-8333-333333333333',
      environmentId: saved.id,
      environmentProfileHash: authoritativeHash,
      savedRepository: bundle.runnerProfile.github.repository,
      pullRequestUrl: 'https://github.com/accordlock/product/pull/42',
      buildRunUrl: 'https://github.com/accordlock/product/actions/runs/987',
      imageDigest: digest('5'),
    });
    const result = await adapter.run(request, bundle, signal);

    expect(authoritativeHash).toBe(digest('9'));
    expect(result.signatureVerified).toBe(true);
    expect(result.receiptPublicKey).toBe(keys.public.receipt_public_key);
    expect(result.receiptKeyId).toBe(keys.public.receipt_key_id);
    expect(result.verificationProfile).toMatchObject({
      schema_version: 2,
      profile_id: saved.id,
      environment_profile_hash: authoritativeHash,
      github: { authority: 'api.github.com' },
      kubernetes: { expected_endpoint: 'https://api.production.eks.example.com' },
      receipt: {
        key_id: keys.public.receipt_key_id,
        public_key: keys.public.receipt_public_key,
      },
    });
    expect(JSON.stringify(result.verificationProfile)).not.toContain('records_directory');
    expect(JSON.stringify(result.verificationProfile)).not.toContain('actor_id');
    expect(invocations.map((entry) => entry.args[0])).toEqual([
      'discover-eks-stdio',
      'init-installation-stdio',
      'profile-hash',
      'profile-hash',
      'check-stdio',
      'verify',
    ]);
    const check = invocations.find((entry) => entry.args[0] === 'check-stdio')!;
    const localEnvelope = JSON.parse(check.stdin!.toString('utf8')) as Record<string, unknown>;
    const credentials = localEnvelope.credentials as Record<string, unknown>;
    expect(credentials).toMatchObject({
      schema_version: 1,
      aws_access_key_id: 'AKIATESTACCESS',
      aws_secret_access_key: 'test-secret-access-key-material',
      aws_session_token: 'test-session-token',
    });
    const profile = check.profile!;
    expect(profile).toMatchObject({
      schema_version: 2,
      profile_id: saved.id,
      environment_id: saved.id,
      github: { authority: 'api.github.com', api_base_path: '/', socket_address: null },
      ecr: { registry_id: '123456789012', region: 'eu-west-3' },
      eks_discovery: { socket_address: null, ca_certificates_der: [] },
      kubernetes: {
        expected_endpoint: 'https://api.production.eks.example.com',
        cluster_name: 'production',
        socket_address: null,
      },
    });
    expect(JSON.stringify(profile)).not.toContain('fixture-token');
  });

  it('rejects a packaged runner whose bytes no longer match the embedded identity', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-runner-adapter-'));
    directories.push(root);
    const bin = path.join(root, 'bin');
    const state = path.join(root, 'state');
    const staged = await stageRunner(bin);
    const { bundle } = await environmentBundle(path.join(root, 'profiles'));
    await fs.appendFile(staged.binary, '-tampered');
    const executeProcess = vi.fn<AccordLockPreflightProcessExecutor>();
    const adapter = new AccordLockBundledPreflightRunner({
      binaryDirectory: bin,
      stateDirectory: state,
      trustStore: new AccordLockPreflightTrustStore({ directory: state, safeStorage }),
      isPackaged: true,
      allowDirtyDevelopment: false,
      expectedBinarySha256: staged.binarySha256,
      expectedProtocolVersion: 1,
      platform: 'win32',
      executeProcess,
    });

    await expect(adapter.profileHash(bundle, new AbortController().signal)).rejects.toThrow(
      'integrity check failed'
    );
    expect(executeProcess).not.toHaveBeenCalled();
  });
});
