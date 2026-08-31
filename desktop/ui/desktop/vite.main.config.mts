// Modified by AccordLock contributors; see UPSTREAM.md.
import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';

function stagedBinaryDigest(markerName: string): string {
  try {
    const marker = JSON.parse(fs.readFileSync(path.resolve('src', 'bin', markerName), 'utf8')) as {
      binary_sha256?: unknown;
    };
    return typeof marker.binary_sha256 === 'string' ? marker.binary_sha256 : '';
  } catch {
    return '';
  }
}

function stagedMarkerField(markerName: string, field: string): unknown {
  try {
    const marker = JSON.parse(
      fs.readFileSync(path.resolve('src', 'bin', markerName), 'utf8')
    ) as Record<string, unknown>;
    return marker[field];
  } catch {
    return undefined;
  }
}

// https://vitejs.dev/config
export default defineConfig({
  define: {
    'process.env.GITHUB_OWNER': JSON.stringify(process.env.GITHUB_OWNER || ''),
    'process.env.GITHUB_REPO': JSON.stringify(process.env.GITHUB_REPO || ''),
    'process.env.GOOSE_BUNDLE_NAME': JSON.stringify(process.env.GOOSE_BUNDLE_NAME || 'AccordLock'),
    __ACCORDLOCK_DEVELOPMENT_PACKAGE__: JSON.stringify(
      process.env.ACCORDLOCK_DEVELOPMENT_BUILD === '1'
    ),
    __ACCORDLOCK_GOOSE_BINARY_SHA256__: JSON.stringify(stagedBinaryDigest('accordlock-build.json')),
    __ACCORDLOCK_RUNTIME_BINARY_SHA256__: JSON.stringify(
      stagedBinaryDigest('accordlock-runtime-build.json')
    ),
    __ACCORDLOCK_PREFLIGHT_BINARY_SHA256__: JSON.stringify(
      stagedMarkerField('accordlock-preflight-runner-build.json', 'binary_sha256') ?? ''
    ),
    __ACCORDLOCK_PREFLIGHT_PROTOCOL_VERSION__: JSON.stringify(
      stagedMarkerField('accordlock-preflight-runner-build.json', 'protocol_version') ?? 0
    ),
  },
});
