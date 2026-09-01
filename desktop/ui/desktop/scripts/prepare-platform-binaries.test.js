// Modified by AccordLock contributors; see UPSTREAM.md.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  _testOnlyAssertNoOwnedPathRedirection: assertNoOwnedPathRedirection,
  _testOnlyAssertWindowsDistributionFilesWithHashPolicy:
    assertWindowsDistributionFilesWithHashPolicy,
  assertAllowedWindowsDistributionHash,
  assertCanonicalStagingDirectory,
  assertMacOSDistributionFiles,
  cleanBinDirectory,
  macOSDistributionFiles,
  macOSSupportFileHashes,
  windowsAuthoredSupportFileHashes,
  windowsDistributionFiles,
  windowsDistributionFileHashPolicy,
  windowsX64PeFiles,
} = require('./prepare-platform-binaries');

const canonicalMacOSSupportDirectory = path.resolve(__dirname, '..', 'src', 'bin');
const canonicalWindowsSupportDirectory = path.resolve(
  __dirname,
  '..',
  'src',
  'platform',
  'windows',
  'bin'
);

const temporaryDirectories = [];

function temporaryDirectory() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'accordlock-windows-payload-test-'));
  temporaryDirectories.push(directory);
  return directory;
}

function writePe(filePath, machine = 0x8664) {
  const bytes = Buffer.alloc(128);
  bytes.writeUInt16LE(0x5a4d, 0);
  bytes.writeUInt32LE(64, 0x3c);
  bytes.writeUInt32LE(0x00004550, 64);
  bytes.writeUInt16LE(machine, 68);
  fs.writeFileSync(filePath, bytes);
}

function writeApprovedDistribution(directory, distributionFiles, peFiles = []) {
  fs.mkdirSync(directory, { recursive: true });
  for (const name of distributionFiles) {
    const filePath = path.join(directory, name);
    if (peFiles.includes(name)) {
      writePe(filePath);
    } else {
      fs.writeFileSync(filePath, `${name}\n`);
    }
  }
  const hashedWindowsFiles = Object.keys(windowsDistributionFileHashPolicy);
  return hashedWindowsFiles.every((name) => fs.existsSync(path.join(directory, name)))
    ? Object.fromEntries(
        hashedWindowsFiles.map((name) => [name, [sha256(path.join(directory, name))]])
      )
    : null;
}

function writeApprovedMacOSDistribution(directory) {
  writeApprovedDistribution(directory, macOSDistributionFiles);
  for (const name of Object.keys(macOSSupportFileHashes)) {
    fs.copyFileSync(path.join(canonicalMacOSSupportDirectory, name), path.join(directory, name));
  }
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test.afterEach(() => {
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop(), { force: true, recursive: true });
  }
});

test('Windows staging keeps only the explicit x86-64 distribution payload', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  for (const name of ['.gitkeep', 'jbang', 'node', 'npx', 'system-tool-wrapper.sh', 'uvx']) {
    fs.writeFileSync(path.join(directory, name), name);
  }

  cleanBinDirectory('win32', directory);
  assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy);

  assert.deepEqual(fs.readdirSync(directory).sort(), [...windowsDistributionFiles]);
});

test('reviewed platform wrappers match their pinned source hashes', () => {
  for (const [name, expectedHash] of Object.entries(windowsAuthoredSupportFileHashes)) {
    assert.equal(sha256(path.join(canonicalWindowsSupportDirectory, name)), expectedHash);
  }
  for (const [name, expectedHash] of Object.entries(macOSSupportFileHashes)) {
    assert.equal(sha256(path.join(canonicalMacOSSupportDirectory, name)), expectedHash);
  }
});

for (const unexpectedName of ['stale.dll', 'unreviewed.exe', 'goose-npm']) {
  test(`Windows staging rejects unapproved payload ${unexpectedName}`, () => {
    const directory = temporaryDirectory();
    writeApprovedDistribution(directory, windowsDistributionFiles, windowsX64PeFiles);
    const unexpectedPath = path.join(directory, unexpectedName);
    if (unexpectedName === 'goose-npm') {
      fs.mkdirSync(unexpectedPath);
    } else {
      fs.writeFileSync(unexpectedPath, 'unapproved');
    }

    assert.throws(
      () => cleanBinDirectory('win32', directory),
      new RegExp(
        `unapproved staged payload: ${unexpectedName.replace('.', '\\.').replace('-', '\\-')}`
      )
    );
  });
}

test('Windows staging rejects an incomplete distribution', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  fs.rmSync(path.join(directory, 'accordlock-agent-runtime.exe'));

  assert.throws(
    () => assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy),
    /missing=\[accordlock-agent-runtime\.exe\]/
  );
});

test('Windows staging rejects an ARM64 executable', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  writePe(path.join(directory, 'goose.exe'), 0xaa64);

  assert.throws(
    () => assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy),
    /goose\.exe must target x86-64 \(PE machine 0xaa64\)/
  );
});

test('Windows staging rehashes an authored command wrapper', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  fs.appendFileSync(path.join(directory, 'jbang.cmd'), 'mutated');

  assert.throws(
    () => assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy),
    /jbang\.cmd checksum mismatch/
  );
});

test('Windows staging rehashes uvx.exe after validating its PE architecture', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  fs.appendFileSync(path.join(directory, 'uvx.exe'), 'mutated');

  assert.throws(
    () => assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy),
    /uvx\.exe checksum mismatch/
  );
});

test('Windows staging rejects a structurally valid but unpinned uv.exe', () => {
  const directory = temporaryDirectory();
  const hashPolicy = writeApprovedDistribution(
    directory,
    windowsDistributionFiles,
    windowsX64PeFiles
  );
  hashPolicy['uv.exe'] = windowsDistributionFileHashPolicy['uv.exe'];

  assert.throws(
    () => assertWindowsDistributionFilesWithHashPolicy(directory, hashPolicy),
    /uv\.exe checksum mismatch/
  );
});

test('Windows uv.exe checksum policy accepts upstream and sanitized reviewed bytes', () => {
  for (const approvedHash of windowsDistributionFileHashPolicy['uv.exe']) {
    assert.doesNotThrow(() =>
      assertAllowedWindowsDistributionHash(
        'uv.exe',
        approvedHash,
        windowsDistributionFileHashPolicy
      )
    );
  }
  assert.equal(windowsDistributionFileHashPolicy['uv.exe'].length, 2);
});

test('macOS staging keeps only the explicit distribution payload', () => {
  const directory = temporaryDirectory();
  writeApprovedMacOSDistribution(directory);
  for (const name of [
    '.gitkeep',
    'goose.exe',
    'accordlock-agent-runtime.exe',
    'accordlock-preflight-runner.exe',
    'jbang.cmd',
    'npx.cmd',
    'uv.exe',
    'uvx.exe',
  ]) {
    fs.writeFileSync(path.join(directory, name), name);
  }

  cleanBinDirectory('darwin', directory);
  assertMacOSDistributionFiles(directory);

  assert.deepEqual(fs.readdirSync(directory).sort(), [...macOSDistributionFiles]);
});

for (const unexpectedName of [
  'temporal',
  'temporal.db',
  'goose-scheduler-executor',
  'temporal-service',
  'stale.dylib',
]) {
  test(`macOS staging rejects unapproved payload ${unexpectedName}`, () => {
    const directory = temporaryDirectory();
    writeApprovedMacOSDistribution(directory);
    const unexpectedPath = path.join(directory, unexpectedName);
    if (unexpectedName === 'temporal') {
      fs.mkdirSync(unexpectedPath);
    } else {
      fs.writeFileSync(unexpectedPath, 'unapproved');
    }

    assert.throws(
      () => cleanBinDirectory('darwin', directory),
      /macOS distribution preparation failed: unapproved staged payload:/
    );
  });
}

test('macOS staging rejects an incomplete distribution', () => {
  const directory = temporaryDirectory();
  writeApprovedMacOSDistribution(directory);
  fs.rmSync(path.join(directory, 'accordlock-agent-runtime'));

  assert.throws(
    () => assertMacOSDistributionFiles(directory),
    /missing=\[accordlock-agent-runtime\]/
  );
});

test('macOS staging rejects a non-regular approved entry', () => {
  const directory = temporaryDirectory();
  writeApprovedMacOSDistribution(directory);
  const wrapperPath = path.join(directory, 'uvx');
  fs.rmSync(wrapperPath);
  fs.mkdirSync(wrapperPath);

  assert.throws(
    () => assertMacOSDistributionFiles(directory),
    /uvx must be one regular non-link file/
  );
});

test('macOS staging rejects a symbolic-link approved entry', (t) => {
  const directory = temporaryDirectory();
  writeApprovedMacOSDistribution(directory);
  const wrapperPath = path.join(directory, 'uvx');
  fs.rmSync(wrapperPath);
  try {
    fs.symlinkSync('npx', wrapperPath, 'file');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`symbolic-link creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  assert.throws(
    () => assertMacOSDistributionFiles(directory),
    /uvx must be one regular non-link file/
  );
});

test('staging rejects a linked or junction directory root', (t) => {
  const container = temporaryDirectory();
  const realDirectory = path.join(container, 'real-bin');
  const linkedDirectory = path.join(container, 'linked-bin');
  writeApprovedMacOSDistribution(realDirectory);
  try {
    fs.symlinkSync(
      realDirectory,
      linkedDirectory,
      process.platform === 'win32' ? 'junction' : 'dir'
    );
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`directory-link creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  assert.throws(
    () => assertMacOSDistributionFiles(linkedDirectory),
    /binary staging (?:path must be one regular non-link directory|directory must not traverse a link or junction)/
  );
});

test('the owned-path guard permits a host alias but rejects redirection below it', (t) => {
  const container = temporaryDirectory();
  const realBoundary = path.join(container, 'real-package');
  const aliasedBoundary = path.join(container, 'host-alias');
  const realBin = path.join(realBoundary, 'src', 'bin');
  fs.mkdirSync(realBin, { recursive: true });
  try {
    fs.symlinkSync(
      realBoundary,
      aliasedBoundary,
      process.platform === 'win32' ? 'junction' : 'dir'
    );
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip(`directory-link creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  assert.doesNotThrow(() =>
    assertNoOwnedPathRedirection(
      path.join(aliasedBoundary, 'src', 'bin'),
      aliasedBoundary,
      'desktop'
    )
  );

  const externalSource = path.join(container, 'external-source');
  const redirectedSource = path.join(realBoundary, 'redirected-source');
  fs.mkdirSync(path.join(externalSource, 'bin'), { recursive: true });
  fs.symlinkSync(
    externalSource,
    redirectedSource,
    process.platform === 'win32' ? 'junction' : 'dir'
  );
  assert.throws(
    () =>
      assertNoOwnedPathRedirection(
        path.join(aliasedBoundary, 'redirected-source', 'bin'),
        aliasedBoundary,
        'desktop'
      ),
    /binary staging path must be one regular non-link directory/
  );
});

test('the production staging guard accepts only the canonical real src/bin directory', () => {
  assert.doesNotThrow(() => assertCanonicalStagingDirectory(canonicalMacOSSupportDirectory));
  const otherDirectory = temporaryDirectory();
  assert.throws(
    () => assertCanonicalStagingDirectory(otherDirectory),
    /binary staging directory must be exactly/
  );
});

test('Forge revalidates the macOS payload before optional signing checks', () => {
  const forgeConfig = fs.readFileSync(path.resolve(__dirname, '..', 'forge.config.ts'), 'utf8');
  const prePackage = forgeConfig.indexOf('prePackage:');
  const canonicalAssertion = forgeConfig.indexOf('assertCanonicalStagingDirectory(', prePackage);
  const darwinBranch = forgeConfig.indexOf("if (platform !== 'darwin')", prePackage);
  const payloadAssertion = forgeConfig.indexOf('assertMacOSDistributionFiles(', darwinBranch);
  const signingBranch = forgeConfig.indexOf('if (!appleSigningEnabled)', payloadAssertion);

  assert.ok(prePackage >= 0);
  assert.ok(canonicalAssertion > prePackage);
  assert.ok(canonicalAssertion < darwinBranch);
  assert.ok(darwinBranch > prePackage);
  assert.ok(payloadAssertion > darwinBranch);
  assert.ok(signingBranch > payloadAssertion);
});

test('Windows build contract pins host, Cargo targets, and excludes wildcard DLL copying', () => {
  const buildScript = fs.readFileSync(
    path.resolve(__dirname, '..', '..', '..', 'scripts', 'build-windows.ps1'),
    'utf8'
  );
  const gooseArguments = /\$gooseCargoArguments\s*=\s*@\((?<body>.*?)\)\s*\r?\n/su.exec(
    buildScript
  );
  const runtimeArguments = /\$runtimeCargoArguments\s*=\s*@\((?<body>.*?)\)\s*\r?\n/su.exec(
    buildScript
  );

  assert.match(buildScript, /\$windowsTargetTriple\s*=\s*"x86_64-pc-windows-msvc"/u);
  assert.match(buildScript, /OSArchitecture\s+-ne\s+\$requiredWindowsArchitecture/u);
  assert.match(buildScript, /ProcessArchitecture\s+-ne\s+\$requiredWindowsArchitecture/u);
  assert.ok(gooseArguments?.groups?.body);
  assert.ok(runtimeArguments?.groups?.body);
  assert.match(gooseArguments.groups.body, /"--target",\s*\$windowsTargetTriple/u);
  assert.match(runtimeArguments.groups.body, /"--target",\s*\$windowsTargetTriple/u);
  assert.doesNotMatch(buildScript, /Get-ChildItem[^\r\n]*\\\*\.dll/iu);
  assert.match(buildScript, /function New-AccordLockCargoTargetDirectory/u);
  assert.match(buildScript, /function Remove-AccordLockCargoTargetDirectory/u);
  assert.match(buildScript, /function Assert-AccordLockStagingDirectory/u);
  assert.match(buildScript, /function Assert-AccordLockReleaseSourceIdentity/u);
  assert.match(
    buildScript,
    /Assert-AccordLockStagingDirectory -SourceRoot \$gooseRepositoryRoot -Directory \$binDir/u
  );
  assert.match(buildScript, /-TargetDirectory \$gooseCargoTargetDirectory/u);
  assert.match(buildScript, /-TargetDirectory \$runtimeCargoTargetDirectory/u);
  assert.match(
    buildScript,
    /Join-Path \$gooseCargoTargetDirectory "\$windowsTargetTriple\\\$profileName\\goose\.exe"/u
  );
  assert.match(
    buildScript,
    /Join-Path \$runtimeCargoTargetDirectory "\$windowsTargetTriple\\\$profileName\\accordlock-agent-runtime\.exe"/u
  );
  assert.doesNotMatch(
    buildScript,
    /Join-Path \$resolvedRuntimeRepo "target\\\$windowsTargetTriple/u
  );
});

test('macOS build contract uses distinct ephemeral release Cargo targets', () => {
  const buildScript = fs.readFileSync(
    path.resolve(__dirname, '..', '..', '..', 'scripts', 'build-macos.ps1'),
    'utf8'
  );

  assert.match(buildScript, /function New-AccordLockCargoTargetDirectory/u);
  assert.match(buildScript, /function Remove-AccordLockCargoTargetDirectory/u);
  assert.match(buildScript, /function Assert-StagingDirectory/u);
  assert.match(buildScript, /function Assert-ReleaseSourceIdentity/u);
  assert.match(
    buildScript,
    /Assert-StagingDirectory -DesktopRoot \$DesktopRoot -Directory \$binDirectory/u
  );
  assert.match(buildScript, /-TargetDirectory \$gooseCargoTargetDirectory/u);
  assert.match(buildScript, /-TargetDirectory \$runtimeCargoTargetDirectory/u);
  assert.match(
    buildScript,
    /Join-Path \$gooseCargoTargetDirectory "\$targetTriple\/release\/goose"/u
  );
  assert.match(
    buildScript,
    /Join-Path \$runtimeCargoTargetDirectory "\$targetTriple\/release\/accordlock-agent-runtime"/u
  );
  assert.doesNotMatch(buildScript, /Join-Path \$GooseRoot "target\/\$targetTriple/u);
  assert.doesNotMatch(buildScript, /Join-Path \$resolvedRuntimeRepo "target\/\$targetTriple/u);
});
