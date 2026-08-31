#!/usr/bin/env node
// Modified by AccordLock contributors; see UPSTREAM.md.
/**
 * Cross-platform i18n check script.
 * Extracts messages to a temp file and compares against the committed file
 * to ensure src/i18n/messages/en.json is up to date.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const projectDir = path.join(__dirname, '..');
const formatjs = require.resolve('@formatjs/cli/bin/formatjs');
const messagesDir = path.join(projectDir, 'src', 'i18n', 'messages');
const enFile = path.join(messagesDir, 'en.json');
const tmpFile = path.join(os.tmpdir(), 'en.i18n-check.json');

const catalogFiles = fs
  .readdirSync(messagesDir)
  .filter((file) => file.endsWith('.json'))
  .sort();
if (catalogFiles.length !== 1 || catalogFiles[0] !== 'en.json') {
  console.error(
    `Error: English-only builds require exactly en.json; found ${catalogFiles.join(', ')}.`
  );
  process.exit(1);
}

execFileSync(
  process.execPath,
  [
    formatjs,
    'extract',
    'src/**/*.{ts,tsx}',
    '--ignore',
    '**/*.d.ts',
    '--out-file',
    tmpFile,
    '--flatten',
  ],
  { stdio: 'inherit', cwd: projectDir }
);

const committed = fs.readFileSync(enFile, 'utf8');
const extracted = fs.readFileSync(tmpFile, 'utf8');

try {
  fs.unlinkSync(tmpFile);
} catch (_) {
  // ignore cleanup errors
}

if (JSON.stringify(JSON.parse(committed)) !== JSON.stringify(JSON.parse(extracted))) {
  console.error(
    'Error: src/i18n/messages/en.json is out of date. Run pnpm i18n:extract to update it.'
  );
  process.exit(1);
}
