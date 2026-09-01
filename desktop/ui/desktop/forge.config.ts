// Modified by AccordLock contributors; see UPSTREAM.md.
const { FusesPlugin } = require('@electron-forge/plugin-fuses');
const { FuseV1Options, FuseVersion } = require('@electron/fuses');
const path = require('node:path');
const { signPackagedWindowsApplication } = require('./scripts/accordlock-windows-signing');
const {
  assertCanonicalStagingDirectory,
  assertMacOSDistributionFiles,
  assertWindowsDistributionFiles,
} = require('./scripts/prepare-platform-binaries');
const { verifyMacOSSidecars } = require('./scripts/verify-accordlock-macos-sidecars');

const isLinuxVulkanBuild = process.env.GOOSE_DESKTOP_LINUX_VARIANT === 'vulkan';
const isAccordLockDevelopmentPackage = process.env.ACCORDLOCK_DEVELOPMENT_BUILD === '1';
const accordLockMacOSSidecarsPreSigned = process.env.ACCORDLOCK_MACOS_PRESIGNED_SIDECARS === '1';
const accordLockMacOSExpectedArchitecture = process.env.ACCORDLOCK_MACOS_EXPECTED_ARCH;
const accordLockForgeOutDir = process.env.ACCORDLOCK_FORGE_OUT_DIR;
const accordLockSquirrelVendorDirectory = process.env.ACCORDLOCK_SQUIRREL_VENDOR_DIRECTORY;
if (accordLockSquirrelVendorDirectory && !path.isAbsolute(accordLockSquirrelVendorDirectory)) {
  throw new Error('ACCORDLOCK_SQUIRREL_VENDOR_DIRECTORY must be an absolute path');
}
if (
  accordLockForgeOutDir &&
  !/^out\/macos\/(?:arm64|x64)$/u.test(accordLockForgeOutDir.replaceAll('\\', '/'))
) {
  throw new Error('ACCORDLOCK_FORGE_OUT_DIR must be out/macos/arm64 or out/macos/x64');
}
const accordLockPublisherOwner = process.env.ACCORDLOCK_GITHUB_OWNER;
const accordLockPublisherRepository = process.env.ACCORDLOCK_GITHUB_REPO;
if (!!accordLockPublisherOwner !== !!accordLockPublisherRepository) {
  throw new Error(
    'AccordLock publishing requires both ACCORDLOCK_GITHUB_OWNER and ACCORDLOCK_GITHUB_REPO'
  );
}
const windowsTimestampUrl = new URL(
  process.env.ACCORDLOCK_WINDOWS_TIMESTAMP_URL || 'https://timestamp.digicert.com'
);
if (
  windowsTimestampUrl.protocol !== 'https:' ||
  windowsTimestampUrl.username ||
  windowsTimestampUrl.password ||
  windowsTimestampUrl.search ||
  windowsTimestampUrl.hash
) {
  throw new Error('ACCORDLOCK_WINDOWS_TIMESTAMP_URL must be a credential-free HTTPS URL');
}
const windowsSignWithParams = `/fd sha256 /tr ${windowsTimestampUrl.toString()} /td sha256`;
const windowsCertificateFile = process.env.WINDOWS_CERTIFICATE_FILE;
const windowsCertificatePassword = process.env.WINDOWS_CERTIFICATE_PASSWORD;
if (!!windowsCertificateFile !== !!windowsCertificatePassword) {
  throw new Error(
    'Windows signing requires both WINDOWS_CERTIFICATE_FILE and WINDOWS_CERTIFICATE_PASSWORD'
  );
}
const windowsSigningEnabled = !!windowsCertificateFile && !!windowsCertificatePassword;
if (isAccordLockDevelopmentPackage && windowsSigningEnabled) {
  throw new Error('AccordLock development packages refuse Windows signing credentials');
}

const appleTeamId = process.env.APPLE_TEAM_ID;
const appleSigningIdentity = process.env.APPLE_SIGNING_IDENTITY;
const appleId = process.env.APPLE_ID;
const appleIdPassword = process.env.APPLE_ID_PASSWORD;
const appleApiKey = process.env.APPLE_API_KEY;
const appleApiKeyId = process.env.APPLE_API_KEY_ID;
const appleApiIssuer = process.env.APPLE_API_ISSUER;
const appleKeychainProfile = process.env.APPLE_KEYCHAIN_PROFILE;
const appleKeychain = process.env.APPLE_KEYCHAIN;
const appleIdCredentialsPresent = !!appleId || !!appleIdPassword;
const appleApiCredentialsPresent = !!appleApiKey || !!appleApiKeyId || !!appleApiIssuer;
const appleKeychainCredentialsPresent = !!appleKeychainProfile || !!appleKeychain;
const appleCredentialModes = [
  appleIdCredentialsPresent,
  appleApiCredentialsPresent,
  appleKeychainCredentialsPresent,
].filter(Boolean).length;
const anyAppleReleaseCredential =
  !!appleTeamId ||
  !!appleSigningIdentity ||
  appleCredentialModes > 0 ||
  !!process.env.KEYCHAIN_PATH;

if (appleIdCredentialsPresent && (!appleId || !appleIdPassword)) {
  throw new Error('Apple ID notarization requires APPLE_ID and APPLE_ID_PASSWORD');
}
if (appleApiCredentialsPresent && (!appleApiKey || !appleApiKeyId || !appleApiIssuer)) {
  throw new Error(
    'App Store Connect notarization requires APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER'
  );
}
if (appleKeychainCredentialsPresent && !appleKeychainProfile) {
  throw new Error('Keychain notarization requires APPLE_KEYCHAIN_PROFILE');
}
if (appleCredentialModes > 1) {
  throw new Error('Configure exactly one Apple notarization credential mode');
}
if (
  anyAppleReleaseCredential &&
  (!appleTeamId || !appleSigningIdentity || appleCredentialModes !== 1)
) {
  throw new Error(
    'macOS release signing requires APPLE_TEAM_ID, APPLE_SIGNING_IDENTITY, and exactly one complete notarization credential mode'
  );
}
if (isAccordLockDevelopmentPackage && anyAppleReleaseCredential) {
  throw new Error('AccordLock development packages reject Apple signing credentials');
}
const appleSigningEnabled = !!appleTeamId && !!appleSigningIdentity && appleCredentialModes === 1;
if (isAccordLockDevelopmentPackage && accordLockMacOSSidecarsPreSigned) {
  throw new Error('AccordLock development packages reject the presigned macOS sidecar mode');
}
if (accordLockMacOSSidecarsPreSigned && !appleSigningEnabled) {
  throw new Error('Presigned macOS sidecars require the complete Apple release identity');
}
if (
  process.platform === 'darwin' &&
  appleSigningEnabled &&
  (!accordLockMacOSSidecarsPreSigned ||
    !['arm64', 'x64'].includes(accordLockMacOSExpectedArchitecture))
) {
  throw new Error(
    'macOS release packaging requires verified presigned sidecars and one exact target architecture'
  );
}

let cfg = {
  name: 'AccordLock',
  executableName: 'AccordLock',
  appBundleId: 'ai.accordlock.desktop',
  appCopyright: 'Copyright © 2026 AccordLock contributors',
  win32metadata: {
    CompanyName: 'AccordLock contributors',
    FileDescription: 'AccordLock',
    InternalName: 'AccordLock',
    OriginalFilename: 'AccordLock.exe',
    ProductName: 'AccordLock',
  },
  asar: true,
  extraResource: [
    'src/bin',
    'src/images',
    'ACCORDLOCK_DISTRIBUTION.md',
    '../../LICENSE',
    '../../NOTICE',
    '../../THIRD_PARTY_NOTICES.md',
  ],
  icon: 'src/images/icon',
  // Recursive Electron Packager signing must remain disabled. Release sidecars
  // are signed and hashed before Vite embeds their digests; postPackage then
  // signs every other PE file and proves that both sidecars stayed byte-exact.
  windowsSign: undefined,
  // Protocol registration
  protocols: [
    {
      name: 'AccordLockProtocol',
      schemes: ['accordlock'],
    },
  ],
  // macOS Info.plist extensions for drag-and-drop support
  extendInfo: {
    // Document types for drag-and-drop support onto dock icon
    CFBundleDocumentTypes: [
      {
        CFBundleTypeName: 'Folders',
        CFBundleTypeRole: 'Viewer',
        LSHandlerRank: 'Alternate',
        LSItemContentTypes: ['public.directory', 'public.folder'],
      },
    ],
    // Usage descriptions for macOS TCC (Transparency, Consent, and Control)
    NSMicrophoneUsageDescription: 'AccordLock needs access to your microphone for voice dictation.',
  },
};

// macOS code signing and notarization via Electron Forge. Release credentials
// are accepted only as one complete, unambiguous authentication profile.
if (appleSigningEnabled) {
  cfg.osxSign = {
    identity: appleSigningIdentity,
    keychain: process.env.KEYCHAIN_PATH || undefined,
    hardenedRuntime: true,
    entitlements: 'entitlements.plist',
    'entitlements-inherit': 'entitlements-inherit.plist',
    ignore: (filePath) =>
      /\/Contents\/Resources\/bin\/(?:goose|accordlock-agent-runtime|accordlock-preflight-runner)$/u.test(
        filePath.replaceAll('\\', '/')
      ),
  };
  cfg.osxNotarize = appleIdCredentialsPresent
    ? {
        appleId,
        appleIdPassword,
        teamId: appleTeamId,
      }
    : appleApiCredentialsPresent
      ? {
          appleApiKey,
          appleApiKeyId,
          appleApiIssuer,
        }
      : {
          keychainProfile: appleKeychainProfile,
          keychain: appleKeychain || undefined,
        };
}

module.exports = {
  ...(accordLockForgeOutDir ? { outDir: accordLockForgeOutDir } : {}),
  packagerConfig: cfg,
  rebuildConfig: {},
  hooks: {
    prePackage: async (_forgeConfig, platform, arch) => {
      const binDirectory = path.resolve(__dirname, 'src', 'bin');
      assertCanonicalStagingDirectory(binDirectory);
      if (platform === 'win32') {
        if (arch !== 'x64') {
          throw new Error(`AccordLock Windows packages must target x64, received ${arch}`);
        }
        assertWindowsDistributionFiles(binDirectory);
        return;
      }
      if (platform !== 'darwin') {
        return;
      }
      if (!['arm64', 'x64'].includes(arch)) {
        throw new Error(`AccordLock macOS packages must target arm64 or x64, received ${arch}`);
      }
      assertMacOSDistributionFiles(binDirectory);
      if (!appleSigningEnabled) {
        return;
      }
      if (arch !== accordLockMacOSExpectedArchitecture) {
        throw new Error(
          `Forge target ${arch} does not match ACCORDLOCK_MACOS_EXPECTED_ARCH=${accordLockMacOSExpectedArchitecture}`
        );
      }
      verifyMacOSSidecars({
        binDirectory,
        expectedTeamId: appleTeamId,
        expectedArchitecture: arch,
      });
    },
    postPackage: async (_forgeConfig, packageResult) => {
      if (packageResult.platform !== 'win32' || !windowsSigningEnabled) {
        return;
      }
      const result = await signPackagedWindowsApplication({
        outputPaths: packageResult.outputPaths,
        signingOptions: {
          certificateFile: windowsCertificateFile,
          certificatePassword: windowsCertificatePassword,
          timestampServer: windowsTimestampUrl.toString(),
        },
        sourceBinDirectory: path.resolve(__dirname, 'src', 'bin'),
      });
      console.log(
        `Signed ${result.signedFiles.length} packaged Windows PE files without modifying AccordLock sidecars`
      );
    },
  },
  publishers:
    accordLockPublisherOwner && accordLockPublisherRepository
      ? [
          {
            name: '@electron-forge/publisher-github',
            config: {
              repository: {
                owner: accordLockPublisherOwner,
                name: accordLockPublisherRepository,
              },
              prerelease: true,
              draft: true,
            },
          },
        ]
      : [],
  makers: [
    {
      name: '@electron-forge/maker-squirrel',
      platforms: ['win32'],
      config: {
        title: 'AccordLock',
        authors: 'AccordLock contributors',
        description:
          'AI agent desktop that works within approved access and produces verifiable execution records',
        name: isAccordLockDevelopmentPackage
          ? 'accordlock_desktop_development'
          : 'accordlock_desktop',
        setupExe: isAccordLockDevelopmentPackage
          ? 'AccordLockDevelopmentSetup.exe'
          : 'AccordLockSetup.exe',
        setupIcon: 'src/images/icon.ico',
        ...(accordLockSquirrelVendorDirectory
          ? { vendorDirectory: accordLockSquirrelVendorDirectory }
          : {}),
        ...(windowsSigningEnabled
          ? {
              certificateFile: windowsCertificateFile,
              certificatePassword: windowsCertificatePassword,
              signWithParams: windowsSignWithParams,
            }
          : {}),
        noMsi: true,
      },
    },
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin', 'win32', 'linux'],
      config: {},
    },
    {
      name: '@electron-forge/maker-deb',
      config: {
        name: 'AccordLock',
        bin: 'AccordLock',
        maintainer: 'AccordLock contributors',
        categories: ['Development'],
        desktopTemplate: './forge.deb.desktop',
        options: {
          icon: 'src/images/icon.png',
          prefix: '/opt',
          ...(isLinuxVulkanBuild ? { depends: ['libvulkan1'] } : {}),
        },
      },
    },
    {
      name: '@electron-forge/maker-rpm',
      config: {
        name: 'AccordLock',
        bin: 'AccordLock',
        maintainer: 'AccordLock contributors',
        categories: ['Development'],
        desktopTemplate: './forge.rpm.desktop',
        options: {
          icon: 'src/images/icon.png',
          prefix: '/opt',
          ...(isLinuxVulkanBuild ? { requires: ['vulkan-loader'] } : {}),
        },
      },
    },
    {
      name: '@electron-forge/maker-flatpak',
      config: {
        options: {
          id: 'ai.accordlock.desktop',
          categories: ['Development'],
          mimeType: ['x-scheme-handler/accordlock'],
          icon: {
            scalable: 'src/images/icon.svg',
            '512x512': 'src/images/icon-512.png',
          },
          runtimeVersion: '25.08',
          baseVersion: '25.08',
          bin: 'AccordLock',
          modules: [
            {
              name: 'libbz2-shim',
              buildsystem: 'simple',
              'build-commands': [
                // Create the lib directory in the app bundle
                'mkdir -p /app/lib',
                // Point to the actual library in the 25.08 runtime
                // We use a wildcard to handle multi-arch paths (x86_64-linux-gnu, etc)
                'ln -s $(find /usr/lib -name "libbz2.so.1" | head -n 1) /app/lib/libbz2.so.1.0',
              ],
            },
            {
              name: 'git',
              buildsystem: 'simple',
              'build-commands': [
                'mkdir -p /app/bin /app/libexec/git-core',
                'cp /usr/bin/git /app/bin/git',
                'cp /usr/libexec/git-core/git-remote-https /app/libexec/git-core/git-remote-https 2>/dev/null || true',
              ],
            },
          ],
          finishArgs: [
            '--share=ipc',
            '--socket=x11',
            '--socket=wayland',
            '--device=dri',
            '--share=network',
            '--filesystem=home',
            '--talk-name=org.freedesktop.Notifications',
            '--socket=session-bus',
            '--socket=system-bus',
            // This ensures the app looks in our shim folder first
            '--env=LD_LIBRARY_PATH=/app/lib',
            '--env=GIT_EXEC_PATH=/app/libexec/git-core',
          ],
        },
      },
    },
  ],
  plugins: [
    {
      name: '@electron-forge/plugin-vite',
      config: {
        build: [
          {
            entry: 'src/main.ts',
            config: 'vite.main.config.mts',
          },
          {
            entry: 'src/preload.ts',
            config: 'vite.preload.config.mts',
          },
        ],
        renderer: [
          {
            name: 'main_window',
            config: 'vite.renderer.config.mts',
          },
        ],
      },
    },
    // Fuses are used to enable/disable various Electron functionality
    // at package time, before code signing the application
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
    }),
  ],
};
