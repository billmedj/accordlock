const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const configurations = Object.freeze({
  '--uv': Object.freeze({
    label: 'uv.exe',
    inputSha256: 'b1645e948603c12dd741987d0c072471195e18dd299b42334477ceac694f0af8',
    outputSha256: '6bd02b05ea03517986f20e7f9abd462bdc7c04ffafac49ee2646c6195ab5b534',
    from: 'C:\\Users\\runneradmin\\',
    to: 'C:\\build\\uv-upstream\\',
    asciiCount: 1248,
    utf16Count: 61,
  }),
  '--squirrel-stub': Object.freeze({
    label: 'Squirrel Setup.exe',
    inputSha256: '1e47eb606dad4c5c1568cfb8f4e970e1051ba5806aedb1ff3256284a8280d83b',
    outputSha256: '7739270d4fd0bd38bfa85008d40cd21495b34da523ac25fc2f7cf692f0f51298',
    from: 'C:\\Users\\ani\\',
    to: 'C:\\build\\src\\',
    asciiCount: 1,
    utf16Count: 0,
  }),
});

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function replaceAllExact(buffer, source, replacement) {
  if (!Buffer.isBuffer(buffer) || !Buffer.isBuffer(source) || !Buffer.isBuffer(replacement)) {
    throw new TypeError('replaceAllExact accepts buffers only');
  }
  if (source.length === 0 || source.length !== replacement.length) {
    throw new Error('Binary path replacements must have the same non-zero byte length');
  }
  let count = 0;
  let offset = 0;
  while ((offset = buffer.indexOf(source, offset)) !== -1) {
    replacement.copy(buffer, offset);
    offset += source.length;
    count += 1;
  }
  return count;
}

function assertNoWindowsUserProfile(buffer, label) {
  const asciiPrefix = Buffer.from('C:\\Users\\', 'utf8');
  const utf16Prefix = Buffer.from('C:\\Users\\', 'utf16le');
  if (buffer.indexOf(asciiPrefix) !== -1 || buffer.indexOf(utf16Prefix) !== -1) {
    throw new Error(`${label} still contains a Windows user-profile path`);
  }
}

function sanitizeBinary(filePath, configuration) {
  const resolvedPath = path.resolve(filePath);
  const item = fs.lstatSync(resolvedPath);
  if (!item.isFile() || item.isSymbolicLink()) {
    throw new Error(`${configuration.label} must be one regular non-link file`);
  }

  const original = fs.readFileSync(resolvedPath);
  const originalDigest = sha256(original);
  if (originalDigest === configuration.outputSha256) {
    assertNoWindowsUserProfile(original, configuration.label);
    return Object.freeze({ changed: false, sha256: originalDigest });
  }
  if (originalDigest !== configuration.inputSha256) {
    throw new Error(`${configuration.label} does not match its pinned input or sanitized digest`);
  }

  const sanitized = Buffer.from(original);
  const asciiCount = replaceAllExact(
    sanitized,
    Buffer.from(configuration.from, 'utf8'),
    Buffer.from(configuration.to, 'utf8')
  );
  const utf16Count = replaceAllExact(
    sanitized,
    Buffer.from(configuration.from, 'utf16le'),
    Buffer.from(configuration.to, 'utf16le')
  );
  if (asciiCount !== configuration.asciiCount || utf16Count !== configuration.utf16Count) {
    throw new Error(
      `${configuration.label} path replacement count changed (ASCII ${asciiCount}, UTF-16LE ${utf16Count})`
    );
  }
  assertNoWindowsUserProfile(sanitized, configuration.label);
  const sanitizedDigest = sha256(sanitized);
  if (sanitizedDigest !== configuration.outputSha256) {
    throw new Error(`${configuration.label} sanitized digest does not match the repository pin`);
  }

  const stagingPath = `${resolvedPath}.accordlock-${process.pid}-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(stagingPath, sanitized, { flag: 'wx', mode: item.mode });
    if (sha256(fs.readFileSync(stagingPath)) !== configuration.outputSha256) {
      throw new Error(`${configuration.label} staging verification failed`);
    }
    fs.copyFileSync(stagingPath, resolvedPath);
  } finally {
    if (fs.existsSync(stagingPath)) {
      fs.unlinkSync(stagingPath);
    }
  }
  if (sha256(fs.readFileSync(resolvedPath)) !== configuration.outputSha256) {
    throw new Error(`${configuration.label} final verification failed`);
  }
  return Object.freeze({ changed: true, sha256: configuration.outputSha256 });
}

function main(argv) {
  if (argv.length !== 2 || !Object.hasOwn(configurations, argv[0])) {
    throw new Error('Usage: node sanitize-windows-build-paths.js <--uv|--squirrel-stub> <file>');
  }
  const configuration = configurations[argv[0]];
  const result = sanitizeBinary(argv[1], configuration);
  console.log(
    `${configuration.label} ${result.changed ? 'sanitized' : 'already sanitized'} (${result.sha256.slice(0, 12)}…)`
  );
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

module.exports = Object.freeze({ assertNoWindowsUserProfile, replaceAllExact, sanitizeBinary });
