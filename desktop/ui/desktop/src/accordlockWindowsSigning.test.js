import { afterEach, describe, expect, it, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  readVerifiedSidecars,
  sha256File,
  signPackagedWindowsApplication,
  signStagedWindowsSidecars,
} = require('../scripts/accordlock-windows-signing.js');

const temporaryDirectories = [];

function temporaryDirectory() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-signing-test-'));
  temporaryDirectories.push(directory);
  return directory;
}

function digest(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function writeReleaseSidecars(binDirectory, suffix = '') {
  fs.mkdirSync(binDirectory, { recursive: true });
  const gooseContent = Buffer.from(`goose${suffix}`);
  const runtimeContent = Buffer.from(`runtime${suffix}`);
  const preflightContent = Buffer.from(`preflight${suffix}`);
  fs.writeFileSync(path.join(binDirectory, 'goose.exe'), gooseContent);
  fs.writeFileSync(path.join(binDirectory, 'accordlock-agent-runtime.exe'), runtimeContent);
  fs.writeFileSync(path.join(binDirectory, 'accordlock-preflight-runner.exe'), preflightContent);
  fs.writeFileSync(
    path.join(binDirectory, 'accordlock-build.json'),
    JSON.stringify({
      schema_version: 2,
      distribution: 'AccordLock',
      policy_feature: 'accordlock-distribution',
      source_commit: 'a'.repeat(40),
      source_dirty: false,
      binary: 'goose.exe',
      binary_sha256: digest(gooseContent),
    })
  );
  fs.writeFileSync(
    path.join(binDirectory, 'accordlock-runtime-build.json'),
    JSON.stringify({
      schema_version: 2,
      distribution: 'AccordLock',
      component: 'accordlock-agent-runtime',
      protocol_version: 2,
      source_commit: 'b'.repeat(40),
      source_dirty: false,
      binary: 'accordlock-agent-runtime.exe',
      binary_sha256: digest(runtimeContent),
    })
  );
  fs.writeFileSync(
    path.join(binDirectory, 'accordlock-preflight-runner-build.json'),
    JSON.stringify({
      schema_version: 1,
      component: 'accordlock-preflight-runner',
      protocol_version: 1,
      binary_sha256: `sha256:${digest(preflightContent)}`,
      source_commit: 'c'.repeat(40),
      dirty: false,
    })
  );
}

function signingOptions(rootDirectory) {
  const certificateFile = path.join(rootDirectory, 'release-certificate.pfx');
  fs.writeFileSync(certificateFile, 'test certificate');
  return {
    certificateFile,
    certificatePassword: 'test-password',
    timestampServer: 'https://timestamp.example.test',
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop(), { force: true, recursive: true });
  }
});

describe('AccordLock Windows signing boundary', () => {
  it('signs sidecars first and replaces every marker digest with signed bytes', async () => {
    const rootDirectory = temporaryDirectory();
    const binDirectory = path.join(rootDirectory, 'bin');
    writeReleaseSidecars(binDirectory);
    const signer = vi.fn(async ({ files }) => {
      for (const file of files) {
        fs.appendFileSync(file, '-signed');
      }
    });

    const signedDigests = await signStagedWindowsSidecars({
      binDirectory,
      signer,
      signingOptions: signingOptions(rootDirectory),
    });

    expect(signer).toHaveBeenCalledTimes(1);
    expect(signer.mock.calls[0][0].files.map((file) => path.basename(file))).toEqual([
      'goose.exe',
      'accordlock-agent-runtime.exe',
      'accordlock-preflight-runner.exe',
    ]);
    expect(signedDigests['goose.exe']).toBe(sha256File(path.join(binDirectory, 'goose.exe')));
    expect(signedDigests['accordlock-agent-runtime.exe']).toBe(
      sha256File(path.join(binDirectory, 'accordlock-agent-runtime.exe'))
    );
    expect(signedDigests['accordlock-preflight-runner.exe']).toBe(
      sha256File(path.join(binDirectory, 'accordlock-preflight-runner.exe'))
    );
    expect(() => readVerifiedSidecars(binDirectory)).not.toThrow();
  });

  it('signs every other packaged PE while excluding protected sidecars', async () => {
    const rootDirectory = temporaryDirectory();
    const sourceBinDirectory = path.join(rootDirectory, 'source-bin');
    writeReleaseSidecars(sourceBinDirectory, '-signed');
    const outputPath = path.join(rootDirectory, 'AccordLock-win32-x64');
    const packagedBinDirectory = path.join(outputPath, 'resources', 'bin');
    fs.mkdirSync(path.dirname(packagedBinDirectory), { recursive: true });
    fs.cpSync(sourceBinDirectory, packagedBinDirectory, { recursive: true });
    fs.writeFileSync(path.join(outputPath, 'AccordLock.exe'), 'desktop');
    fs.writeFileSync(path.join(outputPath, 'chrome.dll'), 'chrome');
    fs.writeFileSync(path.join(outputPath, 'resources', 'native.node'), 'native');
    const originalSidecarDigests = Object.fromEntries(
      readVerifiedSidecars(packagedBinDirectory).map((sidecar) => [
        sidecar.spec.binary,
        sidecar.digest,
      ])
    );
    const signer = vi.fn(async ({ files }) => {
      for (const file of files) {
        fs.appendFileSync(file, '-signed');
      }
    });

    const result = await signPackagedWindowsApplication({
      outputPaths: [outputPath],
      signer,
      signingOptions: signingOptions(rootDirectory),
      sourceBinDirectory,
    });

    expect(result.signedFiles.map((file) => path.basename(file)).sort()).toEqual([
      'AccordLock.exe',
      'chrome.dll',
      'native.node',
    ]);
    expect(result.signedFiles).not.toContain(path.join(packagedBinDirectory, 'goose.exe'));
    expect(result.signedFiles).not.toContain(
      path.join(packagedBinDirectory, 'accordlock-agent-runtime.exe')
    );
    expect(result.signedFiles).not.toContain(
      path.join(packagedBinDirectory, 'accordlock-preflight-runner.exe')
    );
    expect(
      Object.fromEntries(
        readVerifiedSidecars(packagedBinDirectory).map((sidecar) => [
          sidecar.spec.binary,
          sidecar.digest,
        ])
      )
    ).toEqual(originalSidecarDigests);
  });

  it('rejects a sidecar changed before application signing', async () => {
    const rootDirectory = temporaryDirectory();
    const sourceBinDirectory = path.join(rootDirectory, 'source-bin');
    writeReleaseSidecars(sourceBinDirectory, '-signed');
    const outputPath = path.join(rootDirectory, 'AccordLock-win32-x64');
    const packagedBinDirectory = path.join(outputPath, 'resources', 'bin');
    fs.mkdirSync(path.dirname(packagedBinDirectory), { recursive: true });
    fs.cpSync(sourceBinDirectory, packagedBinDirectory, { recursive: true });
    fs.writeFileSync(path.join(outputPath, 'AccordLock.exe'), 'desktop');
    fs.appendFileSync(path.join(packagedBinDirectory, 'goose.exe'), '-tampered');
    const signer = vi.fn();

    await expect(
      signPackagedWindowsApplication({
        outputPaths: [outputPath],
        signer,
        signingOptions: signingOptions(rootDirectory),
        sourceBinDirectory,
      })
    ).rejects.toThrow('goose.exe does not match accordlock-build.json');
    expect(signer).not.toHaveBeenCalled();
  });

  it('detects a signer that mutates an excluded sidecar', async () => {
    const rootDirectory = temporaryDirectory();
    const sourceBinDirectory = path.join(rootDirectory, 'source-bin');
    writeReleaseSidecars(sourceBinDirectory, '-signed');
    const outputPath = path.join(rootDirectory, 'AccordLock-win32-x64');
    const packagedBinDirectory = path.join(outputPath, 'resources', 'bin');
    fs.mkdirSync(path.dirname(packagedBinDirectory), { recursive: true });
    fs.cpSync(sourceBinDirectory, packagedBinDirectory, { recursive: true });
    fs.writeFileSync(path.join(outputPath, 'AccordLock.exe'), 'desktop');
    const signer = vi.fn(async () => {
      fs.appendFileSync(path.join(packagedBinDirectory, 'goose.exe'), '-tampered');
    });

    await expect(
      signPackagedWindowsApplication({
        outputPaths: [outputPath],
        signer,
        signingOptions: signingOptions(rootDirectory),
        sourceBinDirectory,
      })
    ).rejects.toThrow('goose.exe changed during application signing');
  });
});
