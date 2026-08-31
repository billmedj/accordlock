#!/usr/bin/env node
/**
 * Cross-platform i18n compile script.
 * Compiles the English source catalog using formatjs.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const projectDir = path.join(__dirname, '..');
const formatjs = require.resolve('@formatjs/cli/bin/formatjs');
const messagesDir = path.join(projectDir, 'src', 'i18n', 'messages');
const compiledDir = path.join(projectDir, 'src', 'i18n', 'compiled');

fs.mkdirSync(compiledDir, { recursive: true });

for (const file of fs.readdirSync(compiledDir)) {
  if (file.endsWith('.json') && file !== 'en.json') {
    fs.rmSync(path.join(compiledDir, file));
  }
}

const inFile = path.join(messagesDir, 'en.json').split(path.sep).join('/');
const outFile = path.join(compiledDir, 'en.json');
execFileSync(process.execPath, [formatjs, 'compile', inFile, '--out-file', outFile], {
  stdio: 'inherit',
  cwd: projectDir,
});
