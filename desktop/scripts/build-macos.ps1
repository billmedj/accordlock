#requires -Version 7.0

[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [switch]$Development,
    [switch]$Release,
    [Parameter(Mandatory)][ValidateSet('arm64', 'x64')]
    [string]$Architecture,
    [Parameter(Mandatory)][string]$RuntimeRepo,
    [string]$SbomArchivePath,
    [string]$ReleaseLockPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedSyftVersion = '1.51.0'

function Assert-RegularFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        -not [string]::IsNullOrEmpty($item.LinkType) -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Description must be one regular non-link file: '$Path'."
    }
    return $item
}

function Assert-MinimumVersion {
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$RawVersion,
        [Parameter(Mandatory)][version]$MinimumVersion
    )

    try {
        $actualVersion = [version]($RawVersion.Trim() -replace '^v', '')
    }
    catch {
        throw "Could not parse the $Tool version '$RawVersion'."
    }
    if ($actualVersion -lt $MinimumVersion) {
        throw "$Tool $actualVersion is unsupported. Install $MinimumVersion or newer."
    }
}

function Get-SourceIdentity {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][bool]$AllowUncommittedDevelopment
    )

    $resolvedRepository = (Resolve-Path -LiteralPath $Repository -ErrorAction Stop).Path
    $commit = git -c "safe.directory=$resolvedRepository" -C $resolvedRepository rev-parse --verify HEAD 2>$null
    $commitExitCode = $LASTEXITCODE
    $status = git -c "safe.directory=$resolvedRepository" -C $resolvedRepository status --porcelain --untracked-files=all
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the $Component source tree."
    }
    if ($commitExitCode -ne 0 -or [string]::IsNullOrWhiteSpace(($commit -join "`n"))) {
        if (-not $AllowUncommittedDevelopment) {
            throw "Could not resolve a committed $Component source revision."
        }
        return [pscustomobject]@{ Commit = '0' * 40; Dirty = $true }
    }
    $normalizedCommit = ([string]($commit -join "`n")).Trim()
    if ($normalizedCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw "$Component source commit has an invalid format."
    }
    return [pscustomobject]@{
        Commit = $normalizedCommit
        Dirty = -not [string]::IsNullOrWhiteSpace(($status -join "`n"))
    }
}

function Assert-ReleaseSourceIdentity {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$ExpectedCommit
    )

    $identity = Get-SourceIdentity `
        -Repository $Repository `
        -Component $Component `
        -AllowUncommittedDevelopment $false
    if ($identity.Commit -cne $ExpectedCommit -or $identity.Dirty) {
        throw "$Component source changed after the release source lock was verified."
    }
}

function Assert-StagingDirectory {
    param(
        [Parameter(Mandatory)][string]$DesktopRoot,
        [Parameter(Mandatory)][string]$Directory
    )

    $expected = [IO.Path]::GetFullPath((Join-Path $DesktopRoot 'src/bin'))
    $requested = [IO.Path]::GetFullPath($Directory)
    if ($requested -cne $expected) {
        throw "Desktop binary staging must use exactly '$expected'."
    }
    $item = Get-Item -LiteralPath $requested -Force -ErrorAction Stop
    $resolved = (Resolve-Path -LiteralPath $requested -ErrorAction Stop).Path
    if (-not $item.PSIsContainer -or
        -not [string]::IsNullOrEmpty($item.LinkType) -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $resolved -cne $expected) {
        throw 'Desktop binary staging must be one canonical regular non-link directory.'
    }
}

function New-AccordLockCargoTargetDirectory {
    param([Parameter(Mandatory)][string]$SourceRoot)

    $resolvedSourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
    $targetParent = [IO.Path]::GetFullPath((Join-Path $resolvedSourceRoot 'target'))
    if (-not (Test-Path -LiteralPath $targetParent)) {
        New-Item -ItemType Directory -Path $targetParent | Out-Null
    }
    $targetParentItem = Get-Item -LiteralPath $targetParent -Force -ErrorAction Stop
    if ($targetParentItem.PSIsContainer -eq $false -or
        -not [string]::IsNullOrEmpty($targetParentItem.LinkType) -or
        (($targetParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Cargo target parent must be one regular non-link directory: '$targetParent'."
    }

    $leafName = "accordlock-release-cargo-$([guid]::NewGuid().ToString('N'))"
    $candidate = [IO.Path]::GetFullPath((Join-Path $targetParent $leafName))
    if (Test-Path -LiteralPath $candidate) {
        throw "Refusing to reuse a pre-existing release Cargo target directory: '$candidate'."
    }
    New-Item -ItemType Directory -Path $candidate | Out-Null
    $candidateItem = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($candidateItem.PSIsContainer -eq $false -or
        -not [string]::IsNullOrEmpty($candidateItem.LinkType) -or
        (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        @(Get-ChildItem -LiteralPath $candidate -Force).Count -ne 0) {
        throw "Release Cargo target directory must be one new empty non-link directory: '$candidate'."
    }
    return $candidateItem.FullName
}

function Remove-AccordLockCargoTargetDirectory {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$SourceRoot
    )

    $resolvedSourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
    $targetParent = [IO.Path]::GetFullPath((Join-Path $resolvedSourceRoot 'target'))
    $resolvedDirectory = [IO.Path]::GetFullPath($Directory)
    $leafName = Split-Path -Leaf $resolvedDirectory
    if ([IO.Path]::GetDirectoryName($resolvedDirectory) -cne $targetParent -or
        $leafName -cnotmatch '^accordlock-release-cargo-[0-9a-f]{32}$') {
        throw 'Refusing to remove a Cargo target outside the controlled release directory.'
    }
    if (-not (Test-Path -LiteralPath $resolvedDirectory)) {
        return
    }
    $targetParentItem = Get-Item -LiteralPath $targetParent -Force -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolvedDirectory -Force -ErrorAction Stop
    if ($targetParentItem.PSIsContainer -eq $false -or
        -not [string]::IsNullOrEmpty($targetParentItem.LinkType) -or
        (($targetParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $item.PSIsContainer -eq $false -or
        -not [string]::IsNullOrEmpty($item.LinkType) -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Refusing to remove a non-regular release Cargo target directory.'
    }
    Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force
}

function Invoke-ReleaseCargoBuild {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$TargetDirectory,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $saved = @{}
    foreach ($name in @(
        'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_PROFILE_RELEASE_STRIP',
        'CFLAGS', 'CXXFLAGS', 'CARGO_TARGET_DIR'
    )) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $nativeOverrides = @{}
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -match '^(?i:(?:CC|CXX|AR|CFLAGS|CXXFLAGS)(?:_.+)?|(?:TARGET|HOST)_(?:CC|CXX|AR|CFLAGS|CXXFLAGS)|AWS_LC_SYS_.+(?:FLAGS|CC|CXX|AR))$') {
            $nativeOverrides[$entry.Name] = $entry.Value
        }
    }

    $resolvedSource = [IO.Path]::GetFullPath($SourceRoot)
    $resolvedTargetDirectory = [IO.Path]::GetFullPath($TargetDirectory)
    $remaps = [ordered]@{ $resolvedSource = '/_accordlock/source' }
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
        $remaps[[IO.Path]::GetFullPath($userProfile)] = '/_accordlock/build-user'
        $remaps[[IO.Path]::GetFullPath((Join-Path $userProfile '.cargo'))] = '/_accordlock/cargo'
        $remaps[[IO.Path]::GetFullPath((Join-Path $userProfile '.rustup'))] = '/_accordlock/rustup'
    }
    $encodedFlags = @(
        foreach ($entry in $remaps.GetEnumerator()) {
            "--remap-path-prefix=$($entry.Key)=$($entry.Value)"
        }
    ) -join [char]0x1f
    $nativeFlags = @(
        foreach ($entry in $remaps.GetEnumerator()) {
            "-ffile-prefix-map='$($entry.Key)'=$($entry.Value)"
            "-fdebug-prefix-map='$($entry.Key)'=$($entry.Value)"
        }
    ) -join ' '

    try {
        [Environment]::SetEnvironmentVariable('RUSTFLAGS', $null, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', $encodedFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_PROFILE_RELEASE_STRIP', 'symbols', 'Process')
        foreach ($name in $nativeOverrides.Keys) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        [Environment]::SetEnvironmentVariable('CFLAGS', $nativeFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CXXFLAGS', $nativeFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', $resolvedTargetDirectory, 'Process')
        & cargo @Arguments --target-dir $resolvedTargetDirectory
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo release build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        foreach ($name in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
        foreach ($name in $nativeOverrides.Keys) {
            [Environment]::SetEnvironmentVariable($name, $nativeOverrides[$name], 'Process')
        }
    }
}

function Copy-FreshFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Write-Json {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )

    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Update-MarkerDigest {
    param(
        [Parameter(Mandatory)][string]$MarkerPath,
        [Parameter(Mandatory)][string]$BinaryPath,
        [switch]$Prefixed
    )

    $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    $digest = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $marker.binary_sha256 = if ($Prefixed) { "sha256:$digest" } else { $digest }
    Write-Json -Value $marker -Path $MarkerPath
    return $digest
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Program,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Failure
    )

    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $Failure
    }
}

function Assert-RegularDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        -not [string]::IsNullOrEmpty($item.LinkType) -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Description must be one regular non-link directory: '$Path'."
    }
    return $item
}

function Assert-ExactDirectoryEntries {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string[]]$ExpectedNames,
        [Parameter(Mandatory)][string]$Description
    )

    $null = Assert-RegularDirectory -Path $Directory -Description $Description
    $actualNames = @(Get-ChildItem -LiteralPath $Directory -Force | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($ExpectedNames | Sort-Object)
    $difference = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actualNames)
    if ($difference.Count -ne 0) {
        throw "$Description entries differ: expected=[$($expected -join ', ')] actual=[$($actualNames -join ', ')]."
    }
}

function Get-RealDirectoryPath {
    param([Parameter(Mandatory)][string]$Path)

    $realPathScript = @'
const fs = require('node:fs');
const path = require('node:path');
const requested = path.resolve(process.argv[1]);
const real = fs.realpathSync.native(requested);
if (!fs.statSync(real).isDirectory()) {
    throw new Error(`not a directory: ${requested}`);
}
process.stdout.write(real);
'@
    $realPath = & node -e $realPathScript $Path
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$realPath)) {
        throw "Could not resolve the real directory identity for '$Path'."
    }
    return [IO.Path]::GetFullPath(([string]$realPath).Trim())
}

function Assert-ControlledDirectoryChain {
    param(
        [Parameter(Mandatory)][string]$Boundary,
        [Parameter(Mandatory)][string]$Directory,
        [switch]$Create
    )

    $boundaryPath = [IO.Path]::GetFullPath($Boundary)
    $directoryPath = [IO.Path]::GetFullPath($Directory)
    $relativePath = [IO.Path]::GetRelativePath($boundaryPath, $directoryPath)
    if ($relativePath -ceq '.' -or
        $relativePath -ceq '..' -or
        $relativePath.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or
        [IO.Path]::IsPathRooted($relativePath)) {
        throw "Controlled directory '$directoryPath' must be a strict descendant of '$boundaryPath'."
    }

    $boundaryRealPath = Get-RealDirectoryPath -Path $boundaryPath
    $currentPath = $boundaryPath
    foreach ($segment in $relativePath -split '[\\/]') {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            throw "Controlled directory '$directoryPath' contains an empty path segment."
        }
        $currentPath = Join-Path $currentPath $segment
        $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            if (-not $Create) {
                throw "Controlled directory is missing: '$currentPath'."
            }
            New-Item -ItemType Directory -Path $currentPath | Out-Null
        }
        $null = Assert-RegularDirectory -Path $currentPath -Description 'A controlled output directory'
    }

    $directoryRealPath = Get-RealDirectoryPath -Path $directoryPath
    $expectedRealPath = [IO.Path]::GetFullPath((Join-Path $boundaryRealPath $relativePath))
    if ($directoryRealPath -cne $expectedRealPath) {
        throw "Controlled directory '$directoryPath' resolves outside its real boundary."
    }
    return $directoryPath
}

function Remove-ControlledDirectoryTree {
    param(
        [Parameter(Mandatory)][string]$Boundary,
        [Parameter(Mandatory)][string]$Directory
    )

    $item = Get-Item -LiteralPath $Directory -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return
    }
    $validatedPath = Assert-ControlledDirectoryChain -Boundary $Boundary -Directory $Directory
    Remove-Item -LiteralPath $validatedPath -Recurse -Force
}

function Assert-PackagedMacOSApplication {
    param(
        [Parameter(Mandatory)][string]$AppRoot,
        [Parameter(Mandatory)][string]$DesktopRoot,
        [Parameter(Mandatory)][string]$ExpectedLipoArch,
        [System.Collections.IDictionary]$ExpectedPayloadDigests,
        [switch]$RequireCodeSignature
    )

    $null = Assert-RegularDirectory -Path $AppRoot -Description 'A packaged macOS application'
    $packagedBin = Join-Path $AppRoot 'Contents/Resources/bin'
    $distributionGuard = Join-Path $DesktopRoot 'scripts/prepare-platform-binaries.js'
    Invoke-Checked -Program 'node' -Arguments @(
        '-e',
        'require(process.argv[1]).assertMacOSPackagedApplication(process.argv[2])',
        $distributionGuard,
        $AppRoot
    ) -Failure "The packaged application '$AppRoot' differs from the reviewed payload contract."

    if ($null -ne $ExpectedPayloadDigests) {
        foreach ($name in $ExpectedPayloadDigests.Keys) {
            $payloadPath = Join-Path $packagedBin $name
            $null = Assert-RegularFile -Path $payloadPath -Description 'A packaged macOS payload file'
            $actualDigest = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualDigest -cne [string]$ExpectedPayloadDigests[$name]) {
                throw "Packaged payload '$payloadPath' differs from the verified application image."
            }
        }
    }

    foreach ($binary in @(
        (Join-Path $AppRoot 'Contents/MacOS/AccordLock'),
        (Join-Path $packagedBin 'goose'),
        (Join-Path $packagedBin 'accordlock-agent-runtime'),
        (Join-Path $packagedBin 'accordlock-preflight-runner')
    )) {
        $null = Assert-RegularFile -Path $binary -Description 'A packaged macOS executable'
        & /usr/bin/test -x $binary
        if ($LASTEXITCODE -ne 0) {
            throw "Packaged executable '$binary' does not have an executable mode."
        }
        $architectures = (& /usr/bin/lipo -archs $binary).Trim().Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        if ($LASTEXITCODE -ne 0 -or $architectures.Count -ne 1 -or $architectures[0] -cne $ExpectedLipoArch) {
            throw "Packaged executable '$binary' does not contain exactly the $ExpectedLipoArch slice."
        }
    }

    if ($RequireCodeSignature) {
        Invoke-Checked -Program '/usr/bin/codesign' -Arguments @(
            '--verify', '--deep', '--strict', '--verbose=4', $AppRoot
        ) -Failure "The archived application signature is invalid: '$AppRoot'."
        Invoke-Checked -Program '/usr/bin/xcrun' -Arguments @(
            'stapler', 'validate', '-v', $AppRoot
        ) -Failure "The archived application has no valid stapled notarization ticket: '$AppRoot'."
        Invoke-Checked -Program '/usr/sbin/spctl' -Arguments @(
            '--assess', '--type', 'execute', '--verbose=4', $AppRoot
        ) -Failure "Gatekeeper rejected the archived application: '$AppRoot'."
    }
}

function Invoke-NotarySubmit {
    param([Parameter(Mandatory)][string]$Artifact)

    $arguments = @('notarytool', 'submit', $Artifact, '--wait')
    if (-not [string]::IsNullOrWhiteSpace($env:APPLE_KEYCHAIN_PROFILE)) {
        $arguments += @('--keychain-profile', $env:APPLE_KEYCHAIN_PROFILE)
        if (-not [string]::IsNullOrWhiteSpace($env:APPLE_KEYCHAIN)) {
            $arguments += @('--keychain', $env:APPLE_KEYCHAIN)
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:APPLE_API_KEY)) {
        $arguments += @(
            '--key', $env:APPLE_API_KEY,
            '--key-id', $env:APPLE_API_KEY_ID,
            '--issuer', $env:APPLE_API_ISSUER
        )
    }
    else {
        $arguments += @(
            '--apple-id', $env:APPLE_ID,
            '--password', $env:APPLE_ID_PASSWORD,
            '--team-id', $env:APPLE_TEAM_ID
        )
    }
    Invoke-Checked -Program '/usr/bin/xcrun' -Arguments $arguments -Failure "Apple notarization rejected '$Artifact'."
}

if (-not $IsMacOS) {
    throw 'The macOS desktop builder must run on macOS.'
}
if ($Development -eq $Release) {
    throw 'Choose exactly one build kind: -Development or -Release.'
}
if ($AllowDirty -and -not $Development) {
    throw '-AllowDirty is restricted to development builds.'
}
if ($AllowDirty -and $env:ACCORDLOCK_ALLOW_DIRTY_BUILD -cne '1') {
    throw 'Set ACCORDLOCK_ALLOW_DIRTY_BUILD=1 to acknowledge a dirty local development build.'
}

$appleEnvironmentNames = @(
    'APPLE_TEAM_ID', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID', 'APPLE_ID_PASSWORD',
    'APPLE_API_KEY', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER',
    'APPLE_KEYCHAIN_PROFILE', 'APPLE_KEYCHAIN', 'KEYCHAIN_PATH'
)
$appleValues = @{}
foreach ($name in $appleEnvironmentNames) {
    $appleValues[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$appleIdMode = -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_ID) -or -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_ID_PASSWORD)
$apiKeyMode = -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_API_KEY) -or -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_API_KEY_ID) -or -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_API_ISSUER)
$keychainMode = -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_KEYCHAIN_PROFILE) -or -not [string]::IsNullOrWhiteSpace($appleValues.APPLE_KEYCHAIN)
$credentialModes = @($appleIdMode, $apiKeyMode, $keychainMode).Where({ $_ }).Count
$anyAppleCredential = @($appleValues.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0

if ($Development -and $anyAppleCredential) {
    throw 'Development packaging refuses Apple release credentials.'
}
if ($Release) {
    if ($appleValues.APPLE_TEAM_ID -cnotmatch '^[A-Z0-9]{10}$' -or [string]::IsNullOrWhiteSpace($appleValues.APPLE_SIGNING_IDENTITY)) {
        throw 'Release packaging requires APPLE_TEAM_ID and APPLE_SIGNING_IDENTITY.'
    }
    if ($credentialModes -ne 1) {
        throw 'Release packaging requires exactly one complete Apple notarization credential mode.'
    }
    if ($appleIdMode -and ([string]::IsNullOrWhiteSpace($appleValues.APPLE_ID) -or [string]::IsNullOrWhiteSpace($appleValues.APPLE_ID_PASSWORD))) {
        throw 'Apple ID notarization requires APPLE_ID and APPLE_ID_PASSWORD.'
    }
    if ($apiKeyMode -and ([string]::IsNullOrWhiteSpace($appleValues.APPLE_API_KEY) -or [string]::IsNullOrWhiteSpace($appleValues.APPLE_API_KEY_ID) -or [string]::IsNullOrWhiteSpace($appleValues.APPLE_API_ISSUER))) {
        throw 'App Store Connect notarization requires APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER.'
    }
    if ($keychainMode -and [string]::IsNullOrWhiteSpace($appleValues.APPLE_KEYCHAIN_PROFILE)) {
        throw 'Keychain notarization requires APPLE_KEYCHAIN_PROFILE.'
    }
    if ([string]::IsNullOrWhiteSpace($SbomArchivePath)) {
        throw "Release packaging requires the pinned Syft $ExpectedSyftVersion macOS archive."
    }
}

$GooseRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$DesktopRoot = Join-Path $GooseRoot 'ui/desktop'
$resolvedRuntimeRepo = (Resolve-Path -LiteralPath $RuntimeRepo -ErrorAction Stop).Path
$targetTriple = if ($Architecture -ceq 'arm64') { 'aarch64-apple-darwin' } else { 'x86_64-apple-darwin' }
$binDirectory = Join-Path $DesktopRoot 'src/bin'
$outputBase = [IO.Path]::GetFullPath((Join-Path $DesktopRoot 'out'))
$outputPlatformRoot = [IO.Path]::GetFullPath((Join-Path $outputBase 'macos'))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $outputPlatformRoot $Architecture))
$expectedOutputPrefix = $outputBase.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $outputRoot.StartsWith($expectedOutputPrefix, [StringComparison]::Ordinal)) {
    throw 'Refusing to use a macOS output directory outside ui/desktop/out.'
}

foreach ($commandName in @('git', 'cargo', 'rustc', 'node', 'corepack')) {
    if (-not (Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "$commandName is required for the macOS desktop build."
    }
}
$rustcVerboseVersion = @(& rustc -vV)
if ($LASTEXITCODE -ne 0) {
    throw 'Could not inspect the Rust compiler host for macOS packaging.'
}
$rustcHostLines = @($rustcVerboseVersion | Where-Object { $_ -match '^host:\s*(\S+)\s*$' })
if ($rustcHostLines.Count -ne 1) {
    throw 'Rust compiler output did not contain exactly one host triple.'
}
$rustcHost = ([regex]::Match($rustcHostLines[0], '^host:\s*(\S+)\s*$')).Groups[1].Value
if ($rustcHost -cne $targetTriple) {
    throw "macOS packaging requires a native host/target pair: host=$rustcHost target=$targetTriple."
}
foreach ($program in @('/bin/chmod', '/usr/bin/codesign', '/usr/bin/lipo', '/usr/bin/xcrun', '/usr/bin/hdiutil', '/usr/bin/tar', '/usr/bin/test', '/usr/bin/unzip', '/usr/sbin/spctl')) {
    if (-not (Test-Path -LiteralPath $program -PathType Leaf)) {
        throw "Required macOS tool is missing: '$program'."
    }
}
$null = Assert-ControlledDirectoryChain -Boundary $DesktopRoot -Directory $outputBase -Create
$null = Assert-ControlledDirectoryChain -Boundary $outputBase -Directory $outputPlatformRoot -Create
Assert-MinimumVersion -Tool 'Node.js' -RawVersion (& node --version) -MinimumVersion ([version]'24.10.0')
Assert-MinimumVersion -Tool 'Corepack' -RawVersion (& corepack --version) -MinimumVersion ([version]'0.34.0')
Push-Location (Join-Path $GooseRoot 'ui')
try {
    Assert-MinimumVersion -Tool 'pnpm' -RawVersion (& corepack pnpm --version) -MinimumVersion ([version]'10.30.0')
}
finally {
    Pop-Location
}

$releaseLock = $null
if ($Release) {
    if ([string]::IsNullOrWhiteSpace($ReleaseLockPath)) {
        throw 'Release packaging requires -ReleaseLockPath from validated release orchestration.'
    }
    $releaseLock = Get-Content -LiteralPath (Assert-RegularFile -Path $ReleaseLockPath -Description 'The release source lock').FullName -Raw | ConvertFrom-Json -Depth 32
    if ($releaseLock.schema_version -ne 2 -or $releaseLock.publication_state.status -cne 'ready') {
        throw 'Release packaging requires a ready v2 source lock.'
    }
}

$gooseIdentity = Get-SourceIdentity -Repository $GooseRoot -Component 'Goose' -AllowUncommittedDevelopment ($Development -and $AllowDirty)
$runtimeIdentity = Get-SourceIdentity -Repository $resolvedRuntimeRepo -Component 'AccordLock runtime' -AllowUncommittedDevelopment ($Development -and $AllowDirty)
if (($gooseIdentity.Dirty -or $runtimeIdentity.Dirty) -and -not ($Development -and $AllowDirty)) {
    throw 'Dirty source is restricted to an explicitly acknowledged development build.'
}
if ($Release -and ($gooseIdentity.Commit -cne $releaseLock.components.accordlock_goose_distribution.commit -or $runtimeIdentity.Commit -cne $releaseLock.components.accordlock_core.commit)) {
    throw 'The checked-out source commits do not match the validated release lock.'
}

$savedEnvironment = @{}
foreach ($name in @(
    'ACCORDLOCK_DEVELOPMENT_BUILD', 'ACCORDLOCK_MACOS_PRESIGNED_SIDECARS',
    'ACCORDLOCK_MACOS_EXPECTED_ARCH', 'ACCORDLOCK_FORGE_OUT_DIR',
    'ELECTRON_PLATFORM', 'CI'
)) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    [Environment]::SetEnvironmentVariable('ACCORDLOCK_DEVELOPMENT_BUILD', $(if ($Development) { '1' } else { '0' }), 'Process')
    [Environment]::SetEnvironmentVariable('ACCORDLOCK_MACOS_EXPECTED_ARCH', $Architecture, 'Process')
    [Environment]::SetEnvironmentVariable('ACCORDLOCK_FORGE_OUT_DIR', "out/macos/$Architecture", 'Process')
    [Environment]::SetEnvironmentVariable('ELECTRON_PLATFORM', 'darwin', 'Process')
    [Environment]::SetEnvironmentVariable('CI', 'true', 'Process')

    Write-Host "Building AccordLock macOS $Architecture sidecars from locked sources..." -ForegroundColor Cyan
    $gooseCargoTargetDirectory = $null
    $runtimeCargoTargetDirectory = $null
    try {
        $gooseCargoTargetDirectory = if ($Release) {
            New-AccordLockCargoTargetDirectory -SourceRoot $GooseRoot
        } else {
            [IO.Path]::GetFullPath((Join-Path $GooseRoot 'target'))
        }
        $runtimeCargoTargetDirectory = if ($Release) {
            New-AccordLockCargoTargetDirectory -SourceRoot $resolvedRuntimeRepo
        } else {
            [IO.Path]::GetFullPath((Join-Path $resolvedRuntimeRepo 'target'))
        }

        Push-Location $GooseRoot
        try {
            Invoke-ReleaseCargoBuild `
                -SourceRoot $GooseRoot `
                -TargetDirectory $gooseCargoTargetDirectory `
                -Arguments @(
                    'build', '--locked', '--release', '--target', $targetTriple,
                    '-p', 'goose-cli', '--bin', 'goose', '--no-default-features',
                    '--features', 'accordlock-distribution,rustls-tls,system-keyring'
                )
        }
        finally {
            Pop-Location
        }
        Push-Location $resolvedRuntimeRepo
        try {
            Invoke-ReleaseCargoBuild `
                -SourceRoot $resolvedRuntimeRepo `
                -TargetDirectory $runtimeCargoTargetDirectory `
                -Arguments @(
                    'build', '--locked', '--release', '--target', $targetTriple,
                    '-p', 'accordlock-agent-runtime', '--bin', 'accordlock-agent-runtime',
                    '-p', 'accordlock-preflight-runner', '--bin', 'accordlock-preflight-runner'
                )
        }
        finally {
            Pop-Location
        }

        New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null
        Assert-StagingDirectory -DesktopRoot $DesktopRoot -Directory $binDirectory
        $gooseBinary = Join-Path $gooseCargoTargetDirectory "$targetTriple/release/goose"
        $runtimeBinary = Join-Path $runtimeCargoTargetDirectory "$targetTriple/release/accordlock-agent-runtime"
        $preflightBinary = Join-Path $runtimeCargoTargetDirectory "$targetTriple/release/accordlock-preflight-runner"
        foreach ($binary in @($gooseBinary, $runtimeBinary, $preflightBinary)) {
            $null = Assert-RegularFile -Path $binary -Description 'A compiled sidecar'
        }
        Copy-FreshFile -Source $gooseBinary -Destination (Join-Path $binDirectory 'goose')
        Copy-FreshFile -Source $runtimeBinary -Destination (Join-Path $binDirectory 'accordlock-agent-runtime')
        Copy-FreshFile -Source $preflightBinary -Destination (Join-Path $binDirectory 'accordlock-preflight-runner')
        Invoke-Checked -Program '/bin/chmod' -Arguments @(
            '0755',
            (Join-Path $binDirectory 'goose'),
            (Join-Path $binDirectory 'accordlock-agent-runtime'),
            (Join-Path $binDirectory 'accordlock-preflight-runner')
        ) -Failure 'Could not establish deterministic executable modes for the macOS sidecars.'
    }
    finally {
        try {
            if ($Release -and $runtimeCargoTargetDirectory) {
                Remove-AccordLockCargoTargetDirectory `
                    -Directory $runtimeCargoTargetDirectory `
                    -SourceRoot $resolvedRuntimeRepo
            }
        }
        finally {
            if ($Release -and $gooseCargoTargetDirectory) {
                Remove-AccordLockCargoTargetDirectory `
                    -Directory $gooseCargoTargetDirectory `
                    -SourceRoot $GooseRoot
            }
        }
    }

    $gooseDigest = (Get-FileHash -LiteralPath (Join-Path $binDirectory 'goose') -Algorithm SHA256).Hash.ToLowerInvariant()
    $runtimeDigest = (Get-FileHash -LiteralPath (Join-Path $binDirectory 'accordlock-agent-runtime') -Algorithm SHA256).Hash.ToLowerInvariant()
    $preflightDigest = (Get-FileHash -LiteralPath (Join-Path $binDirectory 'accordlock-preflight-runner') -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Json -Path (Join-Path $binDirectory 'accordlock-build.json') -Value ([ordered]@{
        schema_version = 2; distribution = 'AccordLock'; policy_feature = 'accordlock-distribution'
        source_commit = $gooseIdentity.Commit; source_dirty = $gooseIdentity.Dirty
        binary = 'goose'; binary_sha256 = $gooseDigest
    })
    Write-Json -Path (Join-Path $binDirectory 'accordlock-runtime-build.json') -Value ([ordered]@{
        schema_version = 2; distribution = 'AccordLock'; component = 'accordlock-agent-runtime'
        protocol_version = 2; source_commit = $runtimeIdentity.Commit; source_dirty = $runtimeIdentity.Dirty
        binary = 'accordlock-agent-runtime'; binary_sha256 = $runtimeDigest
    })
    Write-Json -Path (Join-Path $binDirectory 'accordlock-preflight-runner-build.json') -Value ([ordered]@{
        schema_version = 1; component = 'accordlock-preflight-runner'; protocol_version = 1
        binary_sha256 = "sha256:$preflightDigest"; source_commit = $runtimeIdentity.Commit; dirty = $runtimeIdentity.Dirty
    })
    Invoke-Checked -Program '/bin/chmod' -Arguments @(
        '0644',
        (Join-Path $binDirectory 'accordlock-build.json'),
        (Join-Path $binDirectory 'accordlock-runtime-build.json'),
        (Join-Path $binDirectory 'accordlock-preflight-runner-build.json')
    ) -Failure 'Could not establish deterministic read modes for the macOS build markers.'

    if ($Release) {
        # Revalidate after compilation, immediately before release signing.
        # This detects persistent or accidental checkout drift. The release
        # boundary assumes an ephemeral, exclusive CI runner; a compromised
        # host able to mutate and restore files concurrently is out of scope.
        Assert-ReleaseSourceIdentity `
            -Repository $GooseRoot `
            -Component 'Goose' `
            -ExpectedCommit $releaseLock.components.accordlock_goose_distribution.commit
        Assert-ReleaseSourceIdentity `
            -Repository $resolvedRuntimeRepo `
            -Component 'AccordLock runtime' `
            -ExpectedCommit $releaseLock.components.accordlock_core.commit

        foreach ($binaryName in @('goose', 'accordlock-agent-runtime', 'accordlock-preflight-runner')) {
            $arguments = @('--force', '--timestamp', '--options', 'runtime', '--sign', $env:APPLE_SIGNING_IDENTITY)
            if (-not [string]::IsNullOrWhiteSpace($env:KEYCHAIN_PATH)) {
                $arguments += @('--keychain', $env:KEYCHAIN_PATH)
            }
            $arguments += Join-Path $binDirectory $binaryName
            Invoke-Checked -Program '/usr/bin/codesign' -Arguments $arguments -Failure "Could not sign $binaryName."
        }
        $gooseDigest = Update-MarkerDigest -MarkerPath (Join-Path $binDirectory 'accordlock-build.json') -BinaryPath (Join-Path $binDirectory 'goose')
        $runtimeDigest = Update-MarkerDigest -MarkerPath (Join-Path $binDirectory 'accordlock-runtime-build.json') -BinaryPath (Join-Path $binDirectory 'accordlock-agent-runtime')
        $preflightDigest = Update-MarkerDigest -MarkerPath (Join-Path $binDirectory 'accordlock-preflight-runner-build.json') -BinaryPath (Join-Path $binDirectory 'accordlock-preflight-runner') -Prefixed
        [Environment]::SetEnvironmentVariable('ACCORDLOCK_MACOS_PRESIGNED_SIDECARS', '1', 'Process')
    }

    $stagedPayloadDigests = $null
    Push-Location $DesktopRoot
    try {
        Invoke-Checked -Program 'node' -Arguments @('scripts/verify-accordlock-backend.js') -Failure 'Sidecar marker verification failed.'
        if ($Release) {
            Invoke-Checked -Program 'node' -Arguments @('scripts/verify-accordlock-macos-sidecars.js') -Failure 'Signed sidecar verification failed.'
        }
        Invoke-Checked -Program 'corepack' -Arguments @('pnpm', 'install', '--frozen-lockfile') -Failure 'Locked desktop dependency installation failed.'
        Invoke-Checked -Program 'node' -Arguments @('scripts/prepare-platform-binaries.js') -Failure 'macOS binary staging failed.'
        Invoke-Checked -Program 'corepack' -Arguments @('pnpm', 'run', 'build-goose-sdk') -Failure 'Desktop SDK build failed.'
        Invoke-Checked -Program 'corepack' -Arguments @('pnpm', 'run', 'i18n:compile') -Failure 'English interface compilation failed.'

        $stagedPayloadDigests = [ordered]@{}
        foreach ($payloadFile in Get-ChildItem -LiteralPath $binDirectory -Force) {
            $payload = Assert-RegularFile -Path $payloadFile.FullName -Description 'A staged macOS payload file'
            $stagedPayloadDigests[$payload.Name] = (Get-FileHash -LiteralPath $payload.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }

        if ($Release) {
            # Forge is a second release boundary after desktop asset generation.
            Assert-ReleaseSourceIdentity `
                -Repository $GooseRoot `
                -Component 'Goose' `
                -ExpectedCommit $releaseLock.components.accordlock_goose_distribution.commit
            Assert-ReleaseSourceIdentity `
                -Repository $resolvedRuntimeRepo `
                -Component 'AccordLock runtime' `
                -ExpectedCommit $releaseLock.components.accordlock_core.commit
        }

        $null = Assert-ControlledDirectoryChain -Boundary $outputBase -Directory $outputPlatformRoot
        Remove-ControlledDirectoryTree -Boundary $outputPlatformRoot -Directory $outputRoot
        Invoke-Checked -Program 'corepack' -Arguments @(
            'pnpm', 'exec', 'electron-forge', 'make', '--platform', 'darwin', '--arch', $Architecture
        ) -Failure 'Electron Forge did not produce the complete macOS artifact set.'
    }
    finally {
        Pop-Location
    }

    $appRoot = Join-Path $outputRoot "AccordLock-darwin-$Architecture/AccordLock.app"
    if (-not (Test-Path -LiteralPath $appRoot -PathType Container)) {
        throw "The packaged application is missing: '$appRoot'."
    }
    $null = Assert-ControlledDirectoryChain -Boundary $outputPlatformRoot -Directory $outputRoot
    $expectedLipoArch = if ($Architecture -ceq 'x64') { 'x86_64' } else { 'arm64' }
    Assert-PackagedMacOSApplication `
        -AppRoot $appRoot `
        -DesktopRoot $DesktopRoot `
        -ExpectedLipoArch $expectedLipoArch `
        -ExpectedPayloadDigests $stagedPayloadDigests

    $dmgOutputDirectory = Join-Path $outputRoot "make/dmg/darwin/$Architecture"
    $null = Assert-ControlledDirectoryChain `
        -Boundary $outputRoot `
        -Directory $dmgOutputDirectory `
        -Create
    $dmgPath = Join-Path $dmgOutputDirectory "AccordLock-darwin-$Architecture.dmg"
    $appContainer = Split-Path -Parent $appRoot
    $applicationsLink = Join-Path $appContainer 'Applications'
    if (Test-Path -LiteralPath $applicationsLink) {
        throw "The DMG staging path already exists: '$applicationsLink'."
    }
    New-Item -ItemType SymbolicLink -Path $applicationsLink -Target '/Applications' | Out-Null
    try {
        Invoke-Checked -Program '/usr/bin/hdiutil' -Arguments @(
            'create', '-volname', 'AccordLock', '-srcfolder', $appContainer,
            '-format', 'UDZO', $dmgPath
        ) -Failure 'The native macOS disk image could not be created.'
    }
    finally {
        Remove-Item -LiteralPath $applicationsLink -Force
    }

    $dmgFiles = @(Get-ChildItem -LiteralPath (Join-Path $outputRoot 'make') -Filter '*.dmg' -File -Recurse)
    $zipFiles = @(Get-ChildItem -LiteralPath (Join-Path $outputRoot 'make') -Filter '*.zip' -File -Recurse)
    if ($dmgFiles.Count -ne 1 -or $zipFiles.Count -ne 1) {
        throw "macOS packaging must emit exactly one DMG and one ZIP per architecture; found $($dmgFiles.Count) DMG and $($zipFiles.Count) ZIP."
    }

    $assurance = [ordered]@{
        apple_team_id = if ($Release) { $env:APPLE_TEAM_ID } else { $null }
        application_code_signature_verified = $false
        gatekeeper_assessment_passed = $false
        application_ticket_stapled = $false
        disk_image_code_signature_verified = $false
        disk_image_notarized_and_stapled = $false
    }
    if ($Release) {
        Invoke-Checked -Program '/usr/bin/codesign' -Arguments @('--verify', '--deep', '--strict', '--verbose=4', $appRoot) -Failure 'The packaged application signature is invalid.'
        Invoke-Checked -Program '/usr/sbin/spctl' -Arguments @('--assess', '--type', 'execute', '--verbose=4', $appRoot) -Failure 'Gatekeeper rejected the packaged application.'
        Invoke-Checked -Program '/usr/bin/xcrun' -Arguments @('stapler', 'validate', '-v', $appRoot) -Failure 'The packaged application has no valid stapled notarization ticket.'
        $assurance.application_code_signature_verified = $true
        $assurance.gatekeeper_assessment_passed = $true
        $assurance.application_ticket_stapled = $true

        Invoke-Checked -Program '/usr/bin/codesign' -Arguments @(
            '--force', '--timestamp', '--sign', $env:APPLE_SIGNING_IDENTITY,
            $dmgFiles[0].FullName
        ) -Failure 'Could not sign the DMG with the Developer ID identity.'
        Invoke-Checked -Program '/usr/bin/codesign' -Arguments @(
            '--verify', '--strict', '--verbose=4', $dmgFiles[0].FullName
        ) -Failure 'The DMG code signature is invalid.'

        Invoke-NotarySubmit -Artifact $dmgFiles[0].FullName
        Invoke-Checked -Program '/usr/bin/xcrun' -Arguments @('stapler', 'staple', '-v', $dmgFiles[0].FullName) -Failure 'Could not staple the DMG notarization ticket.'
        Invoke-Checked -Program '/usr/bin/xcrun' -Arguments @('stapler', 'validate', '-v', $dmgFiles[0].FullName) -Failure 'The DMG has no valid stapled notarization ticket.'
        Invoke-Checked -Program '/usr/bin/codesign' -Arguments @(
            '--verify', '--strict', '--verbose=4', $dmgFiles[0].FullName
        ) -Failure 'The final DMG code signature is invalid after stapling.'
        Invoke-Checked -Program '/usr/sbin/spctl' -Arguments @('--assess', '--type', 'open', '--context', 'context:primary-signature', '--verbose=4', $dmgFiles[0].FullName) -Failure 'Gatekeeper rejected the notarized DMG.'
        $assurance.disk_image_code_signature_verified = $true
        $assurance.disk_image_notarized_and_stapled = $true
    }
    Invoke-Checked -Program '/usr/bin/hdiutil' -Arguments @('verify', $dmgFiles[0].FullName) -Failure 'The DMG structure is invalid.'
    $dmgMountPoint = Join-Path $outputRoot ".dmg-verify-$Architecture"
    if (Test-Path -LiteralPath $dmgMountPoint) {
        throw "Refusing to reuse the DMG verification directory: '$dmgMountPoint'."
    }
    $null = Assert-ControlledDirectoryChain `
        -Boundary $outputRoot `
        -Directory $dmgMountPoint `
        -Create
    $dmgAttached = $false
    try {
        Invoke-Checked -Program '/usr/bin/hdiutil' -Arguments @(
            'attach', '-readonly', '-nobrowse', '-mountpoint', $dmgMountPoint,
            $dmgFiles[0].FullName
        ) -Failure 'The DMG could not be mounted for content verification.'
        $dmgAttached = $true

        Assert-ExactDirectoryEntries `
            -Directory $dmgMountPoint `
            -ExpectedNames @('AccordLock.app', 'Applications') `
            -Description 'The mounted DMG root'
        $mountedApplication = Join-Path $dmgMountPoint 'AccordLock.app'
        $mountedApplicationsLink = Get-Item -LiteralPath (Join-Path $dmgMountPoint 'Applications') -Force
        if ([string]::IsNullOrEmpty($mountedApplicationsLink.LinkType) -or
            [string]$mountedApplicationsLink.Target -cne '/Applications') {
            throw "The DMG Applications entry is not a link to /Applications."
        }
        Assert-PackagedMacOSApplication `
            -AppRoot $mountedApplication `
            -DesktopRoot $DesktopRoot `
            -ExpectedLipoArch $expectedLipoArch `
            -ExpectedPayloadDigests $stagedPayloadDigests `
            -RequireCodeSignature:$Release
    }
    finally {
        if ($dmgAttached) {
            Invoke-Checked -Program '/usr/bin/hdiutil' -Arguments @(
                'detach', $dmgMountPoint
            ) -Failure 'The verified DMG could not be detached.'
        }
        Remove-ControlledDirectoryTree -Boundary $outputRoot -Directory $dmgMountPoint
    }
    Invoke-Checked -Program '/usr/bin/unzip' -Arguments @('-tq', $zipFiles[0].FullName) -Failure 'The ZIP structure is invalid.'
    $zipEntries = @(& /usr/bin/unzip -Z1 $zipFiles[0].FullName)
    if ($LASTEXITCODE -ne 0 -or $zipEntries.Count -eq 0) {
        throw 'The ZIP entry inventory could not be read.'
    }
    foreach ($entry in $zipEntries) {
        $normalizedEntry = ([string]$entry).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($normalizedEntry) -or
            $normalizedEntry.StartsWith('/') -or
            $normalizedEntry -match '^[A-Za-z]:/' -or
            $normalizedEntry -match '(^|/)\.\.(/|$)' -or
            ($normalizedEntry -cne 'AccordLock.app' -and
             -not $normalizedEntry.StartsWith('AccordLock.app/'))) {
            throw "The ZIP contains an entry outside its exact application root: '$entry'."
        }
    }

    $zipVerifyRoot = Join-Path $outputRoot ".zip-verify-$Architecture"
    if (Test-Path -LiteralPath $zipVerifyRoot) {
        throw "Refusing to reuse the ZIP verification directory: '$zipVerifyRoot'."
    }
    $null = Assert-ControlledDirectoryChain `
        -Boundary $outputRoot `
        -Directory $zipVerifyRoot `
        -Create
    try {
        Invoke-Checked -Program '/usr/bin/unzip' -Arguments @(
            '-q', $zipFiles[0].FullName, '-d', $zipVerifyRoot
        ) -Failure 'The ZIP could not be extracted for content verification.'
        Assert-ExactDirectoryEntries `
            -Directory $zipVerifyRoot `
            -ExpectedNames @('AccordLock.app') `
            -Description 'The extracted ZIP root'
        Assert-PackagedMacOSApplication `
            -AppRoot (Join-Path $zipVerifyRoot 'AccordLock.app') `
            -DesktopRoot $DesktopRoot `
            -ExpectedLipoArch $expectedLipoArch `
            -ExpectedPayloadDigests $stagedPayloadDigests `
            -RequireCodeSignature:$Release
    }
    finally {
        Remove-ControlledDirectoryTree -Boundary $outputRoot -Directory $zipVerifyRoot
    }

    $generatedSboms = @()
    if (-not [string]::IsNullOrWhiteSpace($SbomArchivePath)) {
        $sbomScript = Join-Path $GooseRoot 'scripts/generate-release-sboms.ps1'
        $sbomArguments = @(
            '-NoProfile', '-File', $sbomScript,
            '-SyftArchivePath', $SbomArchivePath,
            '-DesktopOutputRoot', $outputRoot,
            '-PackagedAppRoot', $appRoot,
            '-GooseRoot', $GooseRoot,
            '-GooseCommit', $gooseIdentity.Commit,
            '-RuntimeRepo', $resolvedRuntimeRepo,
            '-RuntimeCommit', $runtimeIdentity.Commit
        )
        if ($Release) { $sbomArguments += '-RequireRuntimeSource' }
        & pwsh @sbomArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Offline CycloneDX generation failed.'
        }
        $generatedSboms = @(
            Join-Path $outputRoot 'accordlock-desktop.cdx.json'
            Join-Path $outputRoot 'accordlock-goose-source.cdx.json'
            Join-Path $outputRoot 'accordlock-core-source.cdx.json'
        )
    }
    elseif ($Development) {
        Write-Warning 'This local development package has no SBOM because no pinned Syft archive was supplied.'
    }

    $artifactFiles = @($dmgFiles[0], $zipFiles[0])
    foreach ($sbomPath in $generatedSboms) {
        $artifactFiles += Assert-RegularFile -Path $sbomPath -Description 'A generated SBOM'
    }
    $artifactRecords = @($artifactFiles | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($outputRoot, $_.FullName).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size_bytes = $_.Length
        }
    })
    $manifest = [ordered]@{
        schema_version = 1
        distribution = 'AccordLock'
        build_kind = if ($Release) { 'release' } else { 'development' }
        platform = 'darwin'
        architecture = $Architecture
        source = [ordered]@{
            goose_commit = $gooseIdentity.Commit; goose_dirty = $gooseIdentity.Dirty; goose_binary_sha256 = $gooseDigest
            runtime_commit = $runtimeIdentity.Commit; runtime_dirty = $runtimeIdentity.Dirty; runtime_binary_sha256 = $runtimeDigest
            preflight_commit = $runtimeIdentity.Commit; preflight_dirty = $runtimeIdentity.Dirty; preflight_binary_sha256 = "sha256:$preflightDigest"
        }
        assurance = $assurance
        artifacts = $artifactRecords
    }
    $manifestPath = Join-Path $outputRoot 'accordlock-artifact-manifest.json'
    Write-Json -Value $manifest -Path $manifestPath
    $checksumRecords = @($artifactRecords) + [pscustomobject]@{
        path = 'accordlock-artifact-manifest.json'
        sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $checksumRecords |
        Sort-Object { [string]$_.path } |
        ForEach-Object { "$($_.sha256)  $($_.path)" } |
        Set-Content -LiteralPath (Join-Path $outputRoot 'SHA256SUMS') -Encoding ascii

    Write-Host "AccordLock macOS $Architecture package completed: $outputRoot" -ForegroundColor Green
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
