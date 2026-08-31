import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  loadAccordLockNetworkPolicy,
  normalizeAccordLockNetworkDomains,
  validateAccordLockNetworkDomain,
  writeAccordLockNetworkPolicy,
} from './accordlockNetworkPolicy';

const directories: string[] = [];
const temporaryPolicyPath = (): string => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-network-policy-'));
  directories.push(directory);
  return path.join(directory, 'network.json');
};

afterEach(() => {
  for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true });
});

describe('controlled network policy', () => {
  it('accepts exact public domains and canonicalizes their order', () => {
    expect(normalizeAccordLockNetworkDomains(['status.example.com', 'api.example.com'])).toEqual([
      'api.example.com',
      'status.example.com',
    ]);
  });

  it.each([
    '*.example.com',
    'https://api.example.com',
    'api.example.com:443',
    'Api.example.com',
    'localhost',
    '127.0.0.1',
    'example.com.',
  ])('rejects non-exact or non-public domain %s', (domain) => {
    expect(() => validateAccordLockNetworkDomain(domain)).toThrow();
  });

  it('writes and reloads a committed GET/HEAD-only policy', () => {
    const policyPath = temporaryPolicyPath();
    const written = writeAccordLockNetworkPolicy(policyPath, ['api.example.com']);
    expect(written.allowed_methods).toEqual(['GET', 'HEAD']);
    expect(loadAccordLockNetworkPolicy(policyPath)).toEqual(written);
  });

  it('fails closed if the stored allowlist is modified without a new commitment', () => {
    const policyPath = temporaryPolicyPath();
    writeAccordLockNetworkPolicy(policyPath, ['api.example.com']);
    const stored = JSON.parse(fs.readFileSync(policyPath, 'utf8')) as Record<string, unknown>;
    stored.allowed_domains = ['evil.example.com'];
    fs.writeFileSync(policyPath, JSON.stringify(stored), 'utf8');
    expect(() => loadAccordLockNetworkPolicy(policyPath)).toThrow('commitment');
  });
});
