import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build } from 'vite';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const STATIC_REQUIRE = /\brequire\s*\(\s*(['"])([^'"]+)\1\s*\)/gu;

describe('sandboxed preload bundle', () => {
  let outputDirectory: string;
  let emittedPreload: string;

  beforeAll(async () => {
    outputDirectory = await mkdtemp(path.join(tmpdir(), 'accordlock-preload-'));
    await build({
      configFile: path.resolve(process.cwd(), 'vite.preload.config.mts'),
      build: {
        emptyOutDir: true,
        outDir: outputDirectory,
      },
    });
    emittedPreload = await readFile(path.join(outputDirectory, 'preload.js'), 'utf8');
  }, 30_000);

  afterAll(async () => {
    if (outputDirectory) await rm(outputDirectory, { force: true, recursive: true });
  });

  it('keeps every application dependency inside preload.js', () => {
    const requiredModules = [...emittedPreload.matchAll(STATIC_REQUIRE)].map((match) => match[2]);

    expect([...new Set(requiredModules)]).toEqual(['electron']);
    expect(emittedPreload).not.toContain('require("zod")');
    expect(emittedPreload).not.toContain("require('zod')");
  });
});
