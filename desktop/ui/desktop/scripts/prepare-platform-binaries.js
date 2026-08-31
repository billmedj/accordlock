// Modified by AccordLock contributors; see UPSTREAM.md.
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { SIDECAR_SPECS } = require('./accordlock-windows-signing');

// Paths
const desktopRoot = path.resolve(__dirname, '..');
const srcBinDir = path.join(desktopRoot, 'src', 'bin');
const platformWinDir = path.join(desktopRoot, 'src', 'platform', 'windows', 'bin');
const uvVersion = '0.11.11';
const uvDownloadUrl = `https://github.com/astral-sh/uv/releases/download/${uvVersion}/uv-x86_64-pc-windows-msvc.zip`;
const uvBinaryHashes = {
    'uv.exe': 'b1645e948603c12dd741987d0c072471195e18dd299b42334477ceac694f0af8',
    'uvx.exe': '0305c488dc29c16df1483c02a902d21a6798b0744f8e9eb34271d6b3e4bf6e2a',
};
const accordLockSanitizedUvHash =
    '6bd02b05ea03517986f20e7f9abd462bdc7c04ffafac49ee2646c6195ab5b534';

const windowsAuthoredSupportFiles = Object.freeze(['jbang.cmd', 'npx.cmd']);
const windowsAuthoredSupportFileHashes = Object.freeze({
    'jbang.cmd': '2588d30e4e39865ba05edf2548c5900cf7da65a383f31ede8a45ab4b402cdeba',
    'npx.cmd': '5bbf9c2d45e014dce03ae24e9f2caf653f5134045c9269271777d0cb62039a6c',
});
const windowsDistributionFileHashPolicy = Object.freeze({
    'jbang.cmd': Object.freeze([windowsAuthoredSupportFileHashes['jbang.cmd']]),
    'npx.cmd': Object.freeze([windowsAuthoredSupportFileHashes['npx.cmd']]),
    'uv.exe': Object.freeze([uvBinaryHashes['uv.exe'], accordLockSanitizedUvHash]),
    'uvx.exe': Object.freeze([uvBinaryHashes['uvx.exe']]),
});
const windowsDistributionFiles = Object.freeze(
    [
        ...SIDECAR_SPECS.flatMap(spec => [spec.binary, spec.marker]),
        ...windowsAuthoredSupportFiles,
        ...Object.keys(uvBinaryHashes),
    ].sort()
);
const windowsDistributionFileSet = new Set(windowsDistributionFiles);
const windowsX64PeFiles = Object.freeze(
    [...SIDECAR_SPECS.map(spec => spec.binary), ...Object.keys(uvBinaryHashes)].sort()
);
const windowsSourceOnlyEntries = new Set([
    '.gitkeep',
    'jbang',
    'node',
    'npx',
    'system-tool-wrapper.sh',
    'uvx',
]);
const macOSSupportFiles = Object.freeze([
    'jbang',
    'node',
    'npx',
    'system-tool-wrapper.sh',
    'uvx',
]);
const macOSSupportFileHashes = Object.freeze({
    jbang: '30daf17ccbc0b030d5bec15854ff31a249f650e0ad14a575eb8250e4d983e444',
    node: '38a3e65d6e8c8c554ba54036d596b6183762b396a145d0c3116a683e4501514e',
    npx: '84ad66e6895a1631aa660efd237bfceee5e5bdf2ca1d2b0c759771c504d42bd3',
    'system-tool-wrapper.sh':
        '8473f77e2911c30ea28af25db9c9cde09d55e6b5d94220ad24a297ad46dc07a6',
    uvx: '218c7121887f294b664157d1d4c55737d57aa02fe2accd5d6eb22c8c0dbd47c3',
});
const macOSDistributionFiles = Object.freeze(
    [
        ...SIDECAR_SPECS.flatMap(spec => [spec.binary.replace(/\.exe$/u, ''), spec.marker]),
        ...macOSSupportFiles,
    ].sort()
);
const macOSDistributionFileSet = new Set(macOSDistributionFiles);
const macOSSourceOnlyEntries = new Set([
    '.gitkeep',
    ...windowsAuthoredSupportFiles,
    ...Object.keys(uvBinaryHashes),
    ...SIDECAR_SPECS.map(spec => spec.binary),
]);

// Platform-specific file patterns
const windowsFiles = [
    '*.exe',
    '*.dll',
    '*.cmd',
    'goose-npm/**/*'
];

// Helper function to check if file matches patterns
function matchesPattern(filename, patterns) {
    return patterns.some(pattern => {
        if (pattern.includes('**')) {
            // Handle directory patterns
            const basePattern = pattern.split('/**')[0];
            return filename.startsWith(basePattern);
        } else if (pattern.includes('*')) {
            // Handle wildcard patterns - be more precise with file extensions
            if (pattern.startsWith('*.')) {
                // For file extension patterns like *.exe, *.dll
                const extension = pattern.substring(2); // Remove "*."
                return filename.endsWith('.' + extension);
            } else {
                // For other wildcard patterns
                const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
                return regex.test(filename);
            }
        } else {
            // Exact match
            return filename === pattern;
        }
    });
}

function sha256(filePath) {
    const hash = crypto.createHash('sha256');
    hash.update(fs.readFileSync(filePath));
    return hash.digest('hex');
}

function hasExpectedHash(filePath, expectedHash) {
    return fs.existsSync(filePath) && sha256(filePath) === expectedHash;
}

function failDistribution(platform, message) {
    throw new Error(`AccordLock ${platform} distribution preparation failed: ${message}`);
}

function sameCanonicalPath(left, right) {
    const normalizedLeft = path.normalize(left);
    const normalizedRight = path.normalize(right);
    return process.platform === 'win32'
        ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
        : normalizedLeft === normalizedRight;
}

function assertRealNonLinkDirectory(binDirectory, platform) {
    let directoryStat;
    let realDirectory;
    try {
        directoryStat = fs.lstatSync(binDirectory);
        realDirectory = fs.realpathSync.native(binDirectory);
    } catch {
        failDistribution(platform, `binary staging directory is missing: ${binDirectory}`);
    }
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
        failDistribution(platform, `binary staging path must be one regular non-link directory`);
    }
    if (!sameCanonicalPath(realDirectory, path.resolve(binDirectory))) {
        failDistribution(platform, `binary staging directory must not traverse a link or junction`);
    }
}

function assertCanonicalStagingDirectory(binDirectory = srcBinDir) {
    const expectedDirectory = path.resolve(srcBinDir);
    const requestedDirectory = path.resolve(binDirectory);
    if (!sameCanonicalPath(requestedDirectory, expectedDirectory)) {
        failDistribution(
            'desktop',
            `binary staging directory must be exactly ${expectedDirectory}`
        );
    }
    assertRealNonLinkDirectory(requestedDirectory, 'desktop');
    const realDirectory = fs.realpathSync.native(requestedDirectory);
    if (!sameCanonicalPath(realDirectory, expectedDirectory)) {
        failDistribution(
            'desktop',
            `binary staging real path must be exactly ${expectedDirectory}`
        );
    }
}

function assertRegularNonLinkFile(filePath, label, platform) {
    let stat;
    try {
        stat = fs.lstatSync(filePath);
    } catch {
        failDistribution(platform, `${label} is missing`);
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
        failDistribution(platform, `${label} must be one regular non-link file`);
    }
}

function assertWindowsX64Pe(filePath) {
    assertRegularNonLinkFile(filePath, path.basename(filePath), 'Windows');
    const bytes = fs.readFileSync(filePath);
    if (bytes.length < 64 || bytes.readUInt16LE(0) !== 0x5a4d) {
        failDistribution('Windows', `${path.basename(filePath)} is not a valid PE file`);
    }
    const peOffset = bytes.readUInt32LE(0x3c);
    if (
        peOffset > bytes.length - 6 ||
        bytes.readUInt32LE(peOffset) !== 0x00004550
    ) {
        failDistribution('Windows', `${path.basename(filePath)} has an invalid PE header`);
    }
    const machine = bytes.readUInt16LE(peOffset + 4);
    if (machine !== 0x8664) {
        failDistribution(
            'Windows',
            `${path.basename(filePath)} must target x86-64 (PE machine 0x${machine.toString(16)})`
        );
    }
}

function assertAllowedWindowsDistributionHash(name, actualHash, hashPolicy) {
    const allowedHashes = hashPolicy[name];
    if (!Array.isArray(allowedHashes) || allowedHashes.length === 0) {
        failDistribution('Windows', `${name} has no approved checksum policy`);
    }
    if (!allowedHashes.includes(actualHash)) {
        failDistribution(
            'Windows',
            `${name} checksum mismatch: got ${actualHash}`
        );
    }
}

function assertWindowsDistributionFileHashes(
    binDirectory,
    hashPolicy = windowsDistributionFileHashPolicy
) {
    for (const name of Object.keys(windowsDistributionFileHashPolicy)) {
        assertAllowedWindowsDistributionHash(name, sha256(path.join(binDirectory, name)), hashPolicy);
    }
}

function assertDistributionFiles(binDirectory, platform, expectedFiles, expectedFileSet) {
    let entries;
    assertRealNonLinkDirectory(binDirectory, platform);
    try {
        entries = fs.readdirSync(binDirectory, { withFileTypes: true });
    } catch {
        failDistribution(platform, `binary staging directory is missing: ${binDirectory}`);
    }

    const actualNames = entries.map(entry => entry.name).sort();
    const missing = expectedFiles.filter(name => !actualNames.includes(name));
    const unexpected = actualNames.filter(name => !expectedFileSet.has(name));
    if (missing.length > 0 || unexpected.length > 0) {
        failDistribution(
            platform,
            `staged file set differs: missing=[${missing.join(', ')}] unexpected=[${unexpected.join(', ')}]`
        );
    }

    for (const entry of entries) {
        assertRegularNonLinkFile(path.join(binDirectory, entry.name), entry.name, platform);
    }
}

function assertWindowsDistributionFilesWithHashPolicy(binDirectory, hashPolicy) {
    assertDistributionFiles(
        binDirectory,
        'Windows',
        windowsDistributionFiles,
        windowsDistributionFileSet
    );
    for (const name of windowsX64PeFiles) {
        assertWindowsX64Pe(path.join(binDirectory, name));
    }
    assertWindowsDistributionFileHashes(binDirectory, hashPolicy);
}

function assertWindowsDistributionFiles(binDirectory = srcBinDir) {
    assertWindowsDistributionFilesWithHashPolicy(
        binDirectory,
        windowsDistributionFileHashPolicy
    );
}

function assertMacOSDistributionFiles(binDirectory = srcBinDir) {
    assertDistributionFiles(
        binDirectory,
        'macOS',
        macOSDistributionFiles,
        macOSDistributionFileSet
    );
    for (const [name, expectedHash] of Object.entries(macOSSupportFileHashes)) {
        const actualHash = sha256(path.join(binDirectory, name));
        if (actualHash !== expectedHash) {
            failDistribution(
                'macOS',
                `${name} checksum mismatch: expected ${expectedHash}, got ${actualHash}`
            );
        }
    }
}

function downloadFile(url, destPath, redirectsRemaining = 5) {
    return new Promise((resolve, reject) => {
        https.get(url, response => {
            if (
                response.statusCode >= 300 &&
                response.statusCode < 400 &&
                response.headers.location &&
                redirectsRemaining > 0
            ) {
                response.resume();
                downloadFile(response.headers.location, destPath, redirectsRemaining - 1)
                    .then(resolve)
                    .catch(reject);
                return;
            }

            if (response.statusCode !== 200) {
                response.resume();
                reject(new Error(`Failed to download ${url}: HTTP ${response.statusCode}`));
                return;
            }

            const file = fs.createWriteStream(destPath);
            response.pipe(file);
            file.on('finish', () => file.close(resolve));
            file.on('error', reject);
        }).on('error', reject);
    });
}

function extractZip(zipPath, destDir) {
    if (process.platform === 'win32') {
        execFileSync(
            'powershell.exe',
            [
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-Command',
                `Expand-Archive -LiteralPath '${zipPath.replace(/'/g, "''")}' -DestinationPath '${destDir.replace(/'/g, "''")}' -Force`,
            ],
            { stdio: 'inherit' }
        );
        return;
    }

    execFileSync('unzip', ['-q', zipPath, '-d', destDir], { stdio: 'inherit' });
}

async function ensureWindowsUvBinaries(binDirectory = srcBinDir) {
    const allPresent = Object.entries(uvBinaryHashes).every(([name, expectedHash]) => {
        const filePath = path.join(binDirectory, name);
        return (
            hasExpectedHash(filePath, expectedHash) ||
            (name === 'uv.exe' && hasExpectedHash(filePath, accordLockSanitizedUvHash))
        );
    });

    if (allPresent) {
        console.log(`Pinned uv ${uvVersion} binaries already present`);
        return;
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goose-uv-'));
    const zipPath = path.join(tmpDir, 'uv.zip');
    const extractDir = path.join(tmpDir, 'extract');
    fs.mkdirSync(extractDir, { recursive: true });

    try {
        console.log(`Downloading uv ${uvVersion} from ${uvDownloadUrl}`);
        await downloadFile(uvDownloadUrl, zipPath);
        extractZip(zipPath, extractDir);

        for (const [name, expectedHash] of Object.entries(uvBinaryHashes)) {
            const extractedPath = path.join(extractDir, name);
            if (!fs.existsSync(extractedPath)) {
                throw new Error(`Downloaded uv archive did not contain ${name}`);
            }

            const actualHash = sha256(extractedPath);
            if (actualHash !== expectedHash) {
                throw new Error(
                    `${name} checksum mismatch for uv ${uvVersion}: expected ${expectedHash}, got ${actualHash}`
                );
            }

            const destPath = path.join(binDirectory, name);
            fs.rmSync(destPath, { force: true });
            fs.copyFileSync(extractedPath, destPath);
            console.log(`Copied pinned ${name}`);
        }
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}

// Helper function to clean directory of cross-platform files
function cleanBinDirectory(targetPlatform, binDirectory = srcBinDir) {
    console.log(`Cleaning bin directory for ${targetPlatform} build...`);

    if (!fs.existsSync(binDirectory)) {
        console.log('src/bin directory does not exist, skipping cleanup');
        return;
    }

    const files = fs.readdirSync(binDirectory, { withFileTypes: true });
    
    files.forEach(file => {
        const filePath = path.join(binDirectory, file.name);
        
        if (targetPlatform === 'darwin') {
            if (macOSSourceOnlyEntries.has(file.name)) {
                console.log(`Removing non-macOS support file: ${file.name}`);
                fs.rmSync(filePath, { recursive: true, force: true });
                return;
            }
            if (!macOSDistributionFileSet.has(file.name)) {
                failDistribution('macOS', `unapproved staged payload: ${file.name}`);
            }
        } else if (targetPlatform === 'linux') {
            const isLegacyBackendBinary = file.name === 'goosed';
            if (isLegacyBackendBinary || matchesPattern(file.name, windowsFiles)) {
                const fileType = isLegacyBackendBinary ? 'legacy backend binary' : 'Windows file';
                console.log(`Removing ${fileType}: ${file.name}`);
                if (file.isDirectory()) {
                    fs.rmSync(filePath, { recursive: true, force: true });
                } else {
                    fs.unlinkSync(filePath);
                }
            }
        } else if (targetPlatform === 'win32') {
            if (windowsSourceOnlyEntries.has(file.name)) {
                console.log(`Removing non-Windows support file: ${file.name}`);
                fs.rmSync(filePath, { recursive: true, force: true });
                return;
            }
            if (!windowsDistributionFileSet.has(file.name)) {
                failDistribution('Windows', `unapproved staged payload: ${file.name}`);
            }
        }
    });
}

// Helper function to copy platform-specific files
async function copyPlatformFiles(targetPlatform, binDirectory = srcBinDir) {
    if (targetPlatform === 'win32') {
        console.log('Copying Windows-specific files...');
        
        if (!fs.existsSync(platformWinDir)) {
            console.warn('Windows platform directory does not exist');
            return;
        }

        // Ensure src/bin exists
        if (!fs.existsSync(binDirectory)) {
            fs.mkdirSync(binDirectory, { recursive: true });
        }

        const allowedSourceEntries = new Set([
            ...windowsAuthoredSupportFiles,
            '.gitignore',
            'README.md',
        ]);
        const unexpectedSourceEntries = fs
            .readdirSync(platformWinDir)
            .filter(name => !allowedSourceEntries.has(name));
        if (unexpectedSourceEntries.length > 0) {
            failDistribution(
                'Windows',
                `Windows support source contains unapproved entries: ${unexpectedSourceEntries.sort().join(', ')}`
            );
        }

        for (const name of windowsAuthoredSupportFiles) {
            const srcPath = path.join(platformWinDir, name);
            const destPath = path.join(binDirectory, name);
            assertRegularNonLinkFile(srcPath, `Windows support source ${name}`, 'Windows');
            const expectedHash = windowsAuthoredSupportFileHashes[name];
            const sourceHash = sha256(srcPath);
            if (sourceHash !== expectedHash) {
                failDistribution(
                    'Windows',
                    `Windows support source ${name} checksum mismatch: expected ${expectedHash}, got ${sourceHash}`
                );
            }
            fs.rmSync(destPath, { recursive: true, force: true });
            fs.copyFileSync(srcPath, destPath);
            const stagedHash = sha256(destPath);
            if (stagedHash !== sourceHash) {
                failDistribution(
                    'Windows',
                    `staged Windows support file ${name} does not match its reviewed source`
                );
            }
            console.log(`Copied: ${name}`);
        }

        await ensureWindowsUvBinaries(binDirectory);
    }
}

// Main function
async function preparePlatformBinaries() {
    const targetPlatform = process.env.ELECTRON_PLATFORM || process.platform;
    
    console.log(`Preparing binaries for platform: ${targetPlatform}`);

    assertCanonicalStagingDirectory();
    
    // First copy platform-specific files if needed
    await copyPlatformFiles(targetPlatform);
    
    // Then clean up cross-platform files
    cleanBinDirectory(targetPlatform);

    if (targetPlatform === 'win32') {
        assertWindowsDistributionFiles();
    } else if (targetPlatform === 'darwin') {
        assertMacOSDistributionFiles();
    }
    
    console.log('Platform binary preparation complete');
}

// Run if called directly
if (require.main === module) {
    preparePlatformBinaries().catch(error => {
        console.error(error);
        process.exit(1);
    });
}

module.exports = {
    _testOnlyAssertWindowsDistributionFilesWithHashPolicy:
        assertWindowsDistributionFilesWithHashPolicy,
    assertAllowedWindowsDistributionHash,
    assertCanonicalStagingDirectory,
    assertMacOSDistributionFiles,
    assertWindowsDistributionFiles,
    assertWindowsX64Pe,
    cleanBinDirectory,
    macOSDistributionFiles,
    macOSSupportFileHashes,
    preparePlatformBinaries,
    windowsAuthoredSupportFileHashes,
    windowsDistributionFiles,
    windowsDistributionFileHashPolicy,
    windowsX64PeFiles,
};
