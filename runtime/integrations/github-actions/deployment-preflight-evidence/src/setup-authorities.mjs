#!/usr/bin/env node

import { createAuthoritySetup } from './evidence.mjs';

function parseArguments(argumentsList) {
  let environmentId;
  let showSecrets = false;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    if (argument === '--environment-id' && environmentId === undefined) {
      environmentId = argumentsList[index + 1];
      index += 1;
    } else if (argument === '--show-secrets' && !showSecrets) {
      showSecrets = true;
    } else {
      throw new Error('Invalid setup arguments');
    }
  }
  if (typeof environmentId !== 'string' || !showSecrets) {
    throw new Error('Explicit secret output is required');
  }
  return environmentId;
}

try {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') {
    throw new Error('Authority setup is local-only');
  }
  const environmentId = parseArguments(process.argv.slice(2));
  const setup = createAuthoritySetup(environmentId);
  process.stdout.write(`${JSON.stringify(setup, null, 2)}\n`);
} catch {
  process.stderr.write(
    'Usage: node src/setup-authorities.mjs --environment-id <uuid> --show-secrets\n',
  );
  process.exitCode = 1;
}
