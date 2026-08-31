import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

test('ships as a dependency-free Node 24 action', () => {
  const metadata = fs.readFileSync('action.yml', 'utf8');
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  assert.match(metadata, /using: node24/u);
  assert.match(metadata, /main: src\/action\.mjs/u);
  assert.equal(Object.hasOwn(packageJson, 'dependencies'), false);
  assert.equal(Object.hasOwn(packageJson, 'devDependencies'), false);
  assert.equal(fs.existsSync('node_modules'), false);
});

test('runtime modules import only Node built-ins and local source', () => {
  for (const file of [
    'src/evidence.mjs',
    'src/action.mjs',
    'src/setup-authorities.mjs',
  ]) {
    const source = fs.readFileSync(file, 'utf8');
    const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/gu)].map(
      (match) => match[1],
    );
    assert.ok(
      imports.every((specifier) => specifier.startsWith('node:') || specifier.startsWith('./')),
      `${file} contains an external import`,
    );
  }
});
