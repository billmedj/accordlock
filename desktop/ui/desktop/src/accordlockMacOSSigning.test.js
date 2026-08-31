import { afterEach, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { SIDECARS, verifyMacOSSidecars } = require('../scripts/verify-accordlock-macos-sidecars');

const temporaryDirectories = [];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-macos-signing-'));
  temporaryDirectories.push(directory);
  for (const sidecar of SIDECARS) {
    const bytes = Buffer.from(`signed-${sidecar.binary}`);
    fs.writeFileSync(path.join(directory, sidecar.binary), bytes, { mode: 0o755 });
    fs.writeFileSync(
      path.join(directory, sidecar.marker),
      JSON.stringify({
        [sidecar.digestField]: `${sidecar.digestPrefix || ''}${sha256(bytes)}`,
      })
    );
  }
  return directory;
}

function acceptedSpawn(_command, args) {
  if (args[0] === '-archs') {
    return { status: 0, stdout: 'arm64\n', stderr: '' };
  }
  if (args[0] === '--display') {
    return {
      status: 0,
      stdout: '',
      stderr:
        'Authority=Developer ID Application: AccordLock Contributors (ABCDE12345)\nTeamIdentifier=ABCDE12345\n',
    };
  }
  return { status: 0, stdout: '', stderr: '' };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('macOS sidecar release verification', () => {
  it('binds every signed sidecar to its marker, team, and architecture', () => {
    const verified = verifyMacOSSidecars({
      binDirectory: fixture(),
      expectedTeamId: 'ABCDE12345',
      expectedArchitecture: 'arm64',
      platform: 'darwin',
      spawn: acceptedSpawn,
    });

    expect(verified.map(({ binary }) => binary)).toEqual(SIDECARS.map(({ binary }) => binary));
  });

  it('rejects a sidecar changed after its digest was recorded', () => {
    const directory = fixture();
    fs.appendFileSync(path.join(directory, 'goose'), 'tampered');

    expect(() =>
      verifyMacOSSidecars({
        binDirectory: directory,
        expectedTeamId: 'ABCDE12345',
        expectedArchitecture: 'arm64',
        platform: 'darwin',
        spawn: acceptedSpawn,
      })
    ).toThrow('does not attest the signed goose bytes');
  });

  it('rejects a valid signature from the wrong Apple team', () => {
    const wrongTeamSpawn = (command, args) => {
      const result = acceptedSpawn(command, args);
      if (args[0] === '--display') {
        result.stderr = result.stderr.replaceAll('ABCDE12345', 'WRONG12345');
      }
      return result;
    };

    expect(() =>
      verifyMacOSSidecars({
        binDirectory: fixture(),
        expectedTeamId: 'ABCDE12345',
        expectedArchitecture: 'arm64',
        platform: 'darwin',
        spawn: wrongTeamSpawn,
      })
    ).toThrow('is not signed by Apple Team ABCDE12345');
  });

  it('never reports macOS signature verification from another platform', () => {
    expect(() =>
      verifyMacOSSidecars({
        binDirectory: fixture(),
        expectedTeamId: 'ABCDE12345',
        expectedArchitecture: 'arm64',
        platform: 'win32',
        spawn: acceptedSpawn,
      })
    ).toThrow('cryptographic verification must run on macOS');
  });
});
