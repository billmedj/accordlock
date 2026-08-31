# Modified by AccordLock contributors; see UPSTREAM.md.
# build-windows.ps1
# Build the protected AccordLock Desktop distribution for Windows.
# Run this script from the root of the goose-fork repository in PowerShell
#
# Prerequisites:
#   - Git (https://git-scm.com/download/win)
#   - Rust (https://rustup.rs)
#   - PowerShell 7+ (https://aka.ms/powershell)
#   - Node.js v24+ (https://nodejs.org)
#   - Corepack with pnpm 10.30+
#   - NuGet 7.9.0 from https://dist.nuget.org/win-x86-commandline/v7.9.0/nuget.exe
#
# Usage:
#   cd C:\path\to\accordlock\desktop
#   .\scripts\build-windows.ps1 -Release -ReleaseLockPath C:\path\to\release-manifest.json -RuntimeRepo ..\runtime -NuGetToolPath C:\path\to\nuget.exe
#   $env:ACCORDLOCK_ALLOW_DIRTY_BUILD = "1"
#   .\scripts\build-windows.ps1 -Development -AllowDirty -RuntimeRepo ..\runtime -NuGetToolPath C:\path\to\nuget.exe
#   .\scripts\build-windows.ps1 -PrepareOnly -AllowDirty -RuntimeRepo ..\runtime

param(
    [switch]$AllowDirty,
    [switch]$Development,
    [switch]$PrepareOnly,
    [switch]$ResumeFromVerifiedDesktopBinaries,
    [switch]$Release,
    [string]$RuntimeRepo,
    [string]$RuntimeArtifactsDirectory,
    [string]$SbomToolPath,
    [string]$NuGetToolPath,
    [string]$ReleaseLockPath
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion -lt [version]"7.0.0") {
    Write-Error "AccordLock packaging requires PowerShell 7 or newer (pwsh)."
    exit 1
}

function Assert-MinimumToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string]$RawVersion,
        [Parameter(Mandatory = $true)][version]$MinimumVersion
    )

    $normalizedVersion = $RawVersion.Trim() -replace '^v', ''
    try {
        $actualVersion = [version]$normalizedVersion
    } catch {
        throw "Could not parse the $Tool version '$RawVersion'. Required: $MinimumVersion or newer."
    }
    if ($actualVersion -lt $MinimumVersion) {
        throw "$Tool $actualVersion is unsupported. Install $MinimumVersion or newer."
    }
}

function Resolve-AccordLockSourceIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][bool]$AllowUncommittedDevelopment
    )

    $resolvedRepository = (Resolve-Path -LiteralPath $Repository -ErrorAction Stop).Path
    $rawCommit = git -c "safe.directory=$resolvedRepository" -C $resolvedRepository rev-parse HEAD 2>$null
    $commitExitCode = $LASTEXITCODE
    $statusLines = git -c "safe.directory=$resolvedRepository" -C $resolvedRepository status --porcelain
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the $Component source tree."
    }

    if ($commitExitCode -ne 0 -or [string]::IsNullOrWhiteSpace(($rawCommit -join "`n"))) {
        if (-not $AllowUncommittedDevelopment) {
            throw "Could not resolve a committed $Component source revision."
        }
        return [pscustomobject]@{
            Commit = "0" * 40
            Dirty = $true
        }
    }

    $commit = (($rawCommit -join "`n").Trim())
    if ($commit -cnotmatch '^[0-9a-f]{40}$') {
        throw "$Component source commit has an invalid format."
    }
    return [pscustomobject]@{
        Commit = $commit
        Dirty = -not [string]::IsNullOrWhiteSpace(($statusLines -join "`n"))
    }
}

function Resolve-AccordLockBuildRemaps {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot
    )

    $resolvedSourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    $specialProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $processProfile = [Environment]::GetEnvironmentVariable('USERPROFILE', 'Process')
    $cargoHome = [Environment]::GetEnvironmentVariable('CARGO_HOME', 'Process')
    $rustupHome = [Environment]::GetEnvironmentVariable('RUSTUP_HOME', 'Process')

    $cargoCommand = Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $cargoBinDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($cargoCommand.Source))
    $resolvedCargoHome = if ((Split-Path -Leaf $cargoBinDirectory) -ieq 'bin') {
        Split-Path -Parent $cargoBinDirectory
    } else {
        $cargoBinDirectory
    }

    $rustcCommand = Get-Command rustc -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $rustcSysrootOutput = @(& $rustcCommand.Source --print sysroot)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($rustcSysrootOutput -join "`n"))) {
        throw 'Could not resolve the Rust compiler sysroot for path remapping.'
    }
    $rustcSysroot = [IO.Path]::GetFullPath((($rustcSysrootOutput -join "`n").Trim()))

    $candidates = @(
        [pscustomobject]@{ Path = $specialProfile; Replacement = '/_accordlock/profile-special' }
        [pscustomobject]@{ Path = $processProfile; Replacement = '/_accordlock/profile-process' }
        [pscustomobject]@{ Path = if ($processProfile) { Join-Path $processProfile '.cargo' } else { $null }; Replacement = '/_accordlock/cargo-profile' }
        [pscustomobject]@{ Path = $cargoHome; Replacement = '/_accordlock/cargo-home' }
        [pscustomobject]@{ Path = $resolvedCargoHome; Replacement = '/_accordlock/cargo-resolved' }
        [pscustomobject]@{ Path = if ($processProfile) { Join-Path $processProfile '.rustup' } else { $null }; Replacement = '/_accordlock/rustup-profile' }
        [pscustomobject]@{ Path = $rustupHome; Replacement = '/_accordlock/rustup-home' }
        [pscustomobject]@{ Path = $rustcSysroot; Replacement = '/_accordlock/rustc-sysroot' }
        [pscustomobject]@{ Path = $resolvedSourceRoot; Replacement = '/_accordlock/source' }
    )

    $unique = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate.Path)) {
            continue
        }
        $fullPath = [IO.Path]::GetFullPath([string]$candidate.Path)
        $pathRoot = [IO.Path]::GetPathRoot($fullPath)
        $normalizedPath = $fullPath.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        $normalizedRoot = $pathRoot.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ([string]::IsNullOrWhiteSpace($normalizedPath) -or $normalizedPath -ieq $normalizedRoot) {
            throw "Refusing to remap an empty path or volume root: '$fullPath'."
        }
        $unique[$normalizedPath] = [string]$candidate.Replacement
    }

    return @(
        $unique.GetEnumerator() |
            Sort-Object `
                @{ Expression = { $_.Key.Length }; Descending = $true },
                @{ Expression = { $_.Key }; Descending = $false } |
            ForEach-Object {
                [pscustomobject]@{
                    Root = $_.Key
                    Replacement = $_.Value
                }
            }
    )
}

function ConvertTo-AccordLockUtf16Regex {
    param(
        [Parameter(Mandatory = $true)][string]$Value
    )

    return (@($Value.ToCharArray()) | ForEach-Object {
        [regex]::Escape([string]$_) + '\x00'
    }) -join ''
}

function Assert-AccordLockBinaryPathHygiene {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$SourceRoot
    )

    $binary = Get-Item -LiteralPath $BinaryPath -ErrorAction Stop
    # Cargo may expose its final executable as an ordinary NTFS hard link to
    # the hashed artifact in target/deps. Hard links do not redirect path
    # traversal and are safe to inspect while the handle below denies writes.
    # Symlinks and other reparse points remain forbidden.
    if ($binary.PSIsContainer -or
        (($binary.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Native binary path must be one regular non-reparse file: $BinaryPath"
    }

    $patterns = [Collections.Generic.List[string]]::new()
    $patterns.Add('(?i:[a-z]:[\\/](?:users|documents and settings)[\\/])')
    $patterns.Add('(?i:[a-z]\x00:\x00(?:\\\x00|/\x00)u\x00s\x00e\x00r\x00s\x00(?:\\\x00|/\x00))')
    foreach ($entry in Resolve-AccordLockBuildRemaps -SourceRoot $SourceRoot) {
        foreach ($pathForm in @($entry.Root, $entry.Root.Replace('\', '/'))) {
            $patterns.Add("(?i:$([regex]::Escape($pathForm)))")
            $patterns.Add("(?i:$(ConvertTo-AccordLockUtf16Regex -Value $pathForm))")
        }
    }
    $regex = [regex]::new(
        ($patterns | ForEach-Object { "(?:$_)" }) -join '|',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )

    $stream = [IO.File]::Open(
        $binary.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $buffer = [byte[]]::new(1048576)
        $carry = ''
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $text = $carry + [Text.Encoding]::Latin1.GetString($buffer, 0, $count)
            if ($regex.IsMatch($text)) {
                throw "Native binary embeds a machine-local build path: $($binary.FullName)"
            }
            $carry = if ($text.Length -gt 8192) {
                $text.Substring($text.Length - 8192)
            } else {
                $text
            }
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-AccordLockCargoBuild {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [string[]]$NativePackagesToClean = @(),
        [Parameter(Mandatory = $true)][ref]$ExitCode
    )

    $previousRustFlags = [Environment]::GetEnvironmentVariable('RUSTFLAGS', 'Process')
    $previousEncodedRustFlags = [Environment]::GetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', 'Process')
    $previousReleaseStrip = [Environment]::GetEnvironmentVariable('CARGO_PROFILE_RELEASE_STRIP', 'Process')
    $previousClFlags = [Environment]::GetEnvironmentVariable('CL', 'Process')
    $previousTrailingClFlags = [Environment]::GetEnvironmentVariable('_CL_', 'Process')
    $previousCFlags = [Environment]::GetEnvironmentVariable('CFLAGS', 'Process')
    $previousCxxFlags = [Environment]::GetEnvironmentVariable('CXXFLAGS', 'Process')
    $previousCargoTargetDirectory = [Environment]::GetEnvironmentVariable('CARGO_TARGET_DIR', 'Process')
    $inheritedNativeOverrides = [ordered]@{}
    foreach ($entry in Get-ChildItem Env:) {
        if (
            $entry.Name -cnotin @('CFLAGS', 'CXXFLAGS') -and
            $entry.Name -match '^(?i:(?:CC|CXX|AR|CFLAGS|CXXFLAGS)(?:_.+)?|(?:TARGET|HOST)_(?:CC|CXX|AR|CFLAGS|CXXFLAGS)|AWS_LC_SYS_.+(?:FLAGS|CC|CXX|AR))$'
        ) {
            $inheritedNativeOverrides[$entry.Name] = $entry.Value
        }
    }

    $resolvedSourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    $localTargetDirectory = [IO.Path]::GetFullPath((Join-Path $resolvedSourceRoot 'target'))
    $remaps = @(Resolve-AccordLockBuildRemaps -SourceRoot $resolvedSourceRoot)

    $encodedSeparator = [char]0x1f
    $encodedRustFlags = @(
        foreach ($entry in $remaps) {
            "--remap-path-prefix=$($entry.Root)=$($entry.Replacement)"
        }
    ) -join $encodedSeparator
    $nativeCompilerFlags = @(
        '/experimental:deterministic'
        foreach ($entry in $remaps) {
            $option = "/pathmap:$($entry.Root)=$($entry.Replacement)"
            if ($option -match '\s') {
                "`"$option`""
            } else {
                $option
            }
        }
    ) -join ' '

    try {
        # Packaging must not inherit developer-specific compiler flags. Remap
        # every machine-local Rust and native C/C++ source/cache root and strip
        # symbol tables so packaged sidecars contain no build-machine path.
        [Environment]::SetEnvironmentVariable('RUSTFLAGS', $null, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', $encodedRustFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_PROFILE_RELEASE_STRIP', 'symbols', 'Process')
        [Environment]::SetEnvironmentVariable('CL', $nativeCompilerFlags, 'Process')
        [Environment]::SetEnvironmentVariable('_CL_', $null, 'Process')
        foreach ($name in $inheritedNativeOverrides.Keys) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        [Environment]::SetEnvironmentVariable('CFLAGS', $nativeCompilerFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CXXFLAGS', $nativeCompilerFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', $localTargetDirectory, 'Process')

        # CMake does not always notice a changed CL environment in an existing
        # native object cache. Clean only the explicitly named generated Cargo
        # packages so the remapping policy is applied to every native object.
        foreach ($package in $NativePackagesToClean) {
            & cargo clean --target-dir $localTargetDirectory -p $package
            if ($LASTEXITCODE -ne 0) {
                throw "Could not clean the generated native package '$package'."
            }
        }

        $effectiveArguments = @($Arguments) + @('--target-dir', $localTargetDirectory)
        & cargo @effectiveArguments
        $ExitCode.Value = $LASTEXITCODE
    }
    finally {
        [Environment]::SetEnvironmentVariable('RUSTFLAGS', $previousRustFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', $previousEncodedRustFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_PROFILE_RELEASE_STRIP', $previousReleaseStrip, 'Process')
        [Environment]::SetEnvironmentVariable('CL', $previousClFlags, 'Process')
        [Environment]::SetEnvironmentVariable('_CL_', $previousTrailingClFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CFLAGS', $previousCFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CXXFLAGS', $previousCxxFlags, 'Process')
        [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', $previousCargoTargetDirectory, 'Process')
        foreach ($name in $inheritedNativeOverrides.Keys) {
            [Environment]::SetEnvironmentVariable($name, $inheritedNativeOverrides[$name], 'Process')
        }
    }
}

if ([string]::IsNullOrWhiteSpace($RuntimeRepo) -eq [string]::IsNullOrWhiteSpace($RuntimeArtifactsDirectory)) {
    Write-Host "Specify exactly one trusted runtime source: -RuntimeRepo or -RuntimeArtifactsDirectory." -ForegroundColor Red
    exit 1
}

$developmentMode = $Development -or $PrepareOnly
if ($Release -and $developmentMode) {
    throw "Choose either -Release or a development mode."
}
if (-not $Release -and -not $developmentMode) {
    throw "Choose -Release, -Development, or -PrepareOnly explicitly."
}
if ($ResumeFromVerifiedDesktopBinaries -and (-not $Development -or $PrepareOnly -or $Release)) {
    throw "-ResumeFromVerifiedDesktopBinaries is restricted to -Development builds."
}
if ($ResumeFromVerifiedDesktopBinaries -and [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
    throw "Resuming requires -RuntimeRepo so staged runtime markers can be matched to current source."
}
if ($Release -and [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
    throw "Release packaging requires -RuntimeRepo so the runtime source inventory can be attested."
}
if ($AllowDirty -and -not $developmentMode) {
    throw "-AllowDirty is restricted to -Development or -PrepareOnly builds."
}
if ($AllowDirty -and $env:ACCORDLOCK_ALLOW_DIRTY_BUILD -cne "1") {
    throw "Set ACCORDLOCK_ALLOW_DIRTY_BUILD=1 to acknowledge a dirty local development build."
}
if (
    $Development -and
    (-not [string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_FILE) -or
     -not [string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_PASSWORD))
) {
    throw "Development packaging refuses Windows code-signing credentials. Use the release pipeline for signed artifacts."
}

$releaseLock = $null
$releaseCertificateFile = $null
$releaseCertificatePassword = $null
if ($Release) {
    if ([string]::IsNullOrWhiteSpace($ReleaseLockPath)) {
        throw "Release packaging requires -ReleaseLockPath from validated release orchestration."
    }
    $releaseLockItem = Get-Item -LiteralPath $ReleaseLockPath -ErrorAction Stop
    if ($releaseLockItem.PSIsContainer -or -not [string]::IsNullOrEmpty($releaseLockItem.LinkType)) {
        throw "The release source lock must be one regular non-link file."
    }
    $resolvedReleaseLockPath = $releaseLockItem.FullName
    try {
        $releaseLock = Get-Content -LiteralPath $resolvedReleaseLockPath -Raw | ConvertFrom-Json -Depth 32
    } catch {
        throw "The release source lock is not valid JSON."
    }
    if ($releaseLock.schema_version -ne 2 -or $releaseLock.publication_state.status -cne "ready") {
        throw "Release packaging requires a ready v2 source lock."
    }
    foreach ($componentName in @("accordlock_goose_distribution", "accordlock_core")) {
        $component = $releaseLock.components.$componentName
        if (
            $null -eq $component -or
            [string]::IsNullOrWhiteSpace($component.repository) -or
            $component.commit -cnotmatch '^[0-9a-f]{40}$'
        ) {
            throw "Release source lock component '$componentName' is not publicly pinned."
        }
    }
    if (
        [string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_FILE) -or
        [string]::IsNullOrWhiteSpace($env:WINDOWS_CERTIFICATE_PASSWORD)
    ) {
        throw "Release packaging requires Windows code-signing credentials."
    }
    $certificateItem = Get-Item -LiteralPath $env:WINDOWS_CERTIFICATE_FILE -ErrorAction Stop
    if ($certificateItem.PSIsContainer -or -not [string]::IsNullOrEmpty($certificateItem.LinkType)) {
        throw "WINDOWS_CERTIFICATE_FILE must identify one regular non-link file."
    }
    $releaseCertificateFile = $certificateItem.FullName
    $releaseCertificatePassword = $env:WINDOWS_CERTIFICATE_PASSWORD
    [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_FILE', $null, 'Process')
    [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_PASSWORD', $null, 'Process')
}

# This value is compiled into the Electron main process. Force it off for every
# release build so an inherited developer environment cannot weaken packaged
# runtime marker validation.
$env:ACCORDLOCK_DEVELOPMENT_BUILD = if ($developmentMode) { "1" } else { "0" }

$expectedSyftVersion = "1.51.0"
$expectedSyftBinarySha256 = "75adfff66c266adac51fe8addeca97702f82b4d822d02bf70b79f556c84d3a46"
$expectedNuGetVersion = "7.9.0.83"
$expectedNuGetBinarySha256 = "992d70cac5b06c38efec91806caba64cdcc07e6d963a0959dbbbaf264d33b800"
$syftConfigurationPath = Join-Path $PSScriptRoot "syft-release.yaml"
$sbomGenerationScript = Join-Path $PSScriptRoot "generate-release-sboms.ps1"
if (-not (Test-Path -LiteralPath $syftConfigurationPath -PathType Leaf)) {
    throw "The pinned offline SBOM configuration is missing."
}
if (-not (Test-Path -LiteralPath $sbomGenerationScript -PathType Leaf)) {
    throw "The pinned SBOM generation helper is missing."
}
$syftExecutable = $null
if (-not [string]::IsNullOrWhiteSpace($SbomToolPath)) {
    $syftItem = Get-Item -LiteralPath $SbomToolPath -ErrorAction Stop
    if ($syftItem.PSIsContainer -or -not [string]::IsNullOrEmpty($syftItem.LinkType)) {
        throw "The SBOM tool must be one regular non-link file."
    }
    $syftExecutable = $syftItem.FullName
} else {
    $syftCommand = Get-Command "syft" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($syftCommand) {
        $syftExecutable = $syftCommand.Source
    }
}
if ($Release -and -not $syftExecutable) {
    throw "Release packaging requires Syft $expectedSyftVersion to generate the packaged-application SBOM."
}
if ($syftExecutable) {
    $syftDigest = (Get-FileHash -LiteralPath $syftExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($syftDigest -cne $expectedSyftBinarySha256) {
        throw "The SBOM tool binary does not match the repository checksum pin."
    }
}

$nuGetExecutable = $null
if (-not $PrepareOnly) {
    if ([string]::IsNullOrWhiteSpace($NuGetToolPath)) {
        throw "Windows packaging requires the pinned NuGet 7.9.0 executable through -NuGetToolPath."
    }
    $nuGetItem = Get-Item -LiteralPath $NuGetToolPath -Force -ErrorAction Stop
    if (
        $nuGetItem.PSIsContainer -or
        -not [string]::IsNullOrEmpty($nuGetItem.LinkType) -or
        (($nuGetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    ) {
        throw "The NuGet tool must be one regular non-link file."
    }
    $nuGetExecutable = $nuGetItem.FullName
    $nuGetDigest = (Get-FileHash -LiteralPath $nuGetExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($nuGetDigest -cne $expectedNuGetBinarySha256) {
        throw "The NuGet tool binary does not match the repository checksum pin."
    }
    if ($nuGetItem.VersionInfo.FileVersion -cne $expectedNuGetVersion) {
        throw "Expected NuGet file version $expectedNuGetVersion; found '$($nuGetItem.VersionInfo.FileVersion)'."
    }
    $nuGetSignature = Get-AuthenticodeSignature -LiteralPath $nuGetExecutable
    if (
        $nuGetSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $nuGetSignature.SignerCertificate -or
        -not $nuGetSignature.SignerCertificate.Subject.StartsWith(
            'CN=Microsoft Corporation,',
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "The NuGet tool must carry a valid Microsoft Authenticode signature."
    }
}

function Assert-AccordLockRuntimeArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][bool]$AllowDirtyDevelopment
    )

    $resolvedDirectory = (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $runtimeBinaryPath = Join-Path $resolvedDirectory "accordlock-agent-runtime.exe"
    $runtimeMarkerPath = Join-Path $resolvedDirectory "accordlock-runtime-build.json"
    $preflightBinaryPath = Join-Path $resolvedDirectory "accordlock-preflight-runner.exe"
    $preflightMarkerPath = Join-Path $resolvedDirectory "accordlock-preflight-runner-build.json"
    foreach ($requiredFile in @($runtimeBinaryPath, $runtimeMarkerPath, $preflightBinaryPath, $preflightMarkerPath)) {
        $item = Get-Item -LiteralPath $requiredFile -ErrorAction Stop
        if (-not $item.PSIsContainer -and [string]::IsNullOrEmpty($item.LinkType)) {
            continue
        }
        throw "Runtime artifact must be a regular non-link file: $requiredFile"
    }

    try {
        $runtimeMarker = Get-Content -LiteralPath $runtimeMarkerPath -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid AccordLock runtime marker JSON: $($_.Exception.Message)"
    }
    $expectedFields = @(
        "binary",
        "binary_sha256",
        "component",
        "distribution",
        "protocol_version",
        "schema_version",
        "source_commit",
        "source_dirty"
    ) | Sort-Object
    $actualFields = @($runtimeMarker.PSObject.Properties.Name) | Sort-Object
    if (Compare-Object -ReferenceObject $expectedFields -DifferenceObject $actualFields) {
        throw "AccordLock runtime marker fields are missing or unexpected."
    }
    if (
        $runtimeMarker.schema_version -ne 2 -or
        $runtimeMarker.distribution -cne "AccordLock" -or
        $runtimeMarker.component -cne "accordlock-agent-runtime" -or
        $runtimeMarker.protocol_version -ne 2
    ) {
        throw "AccordLock runtime marker identifies an incompatible component."
    }
    if ($runtimeMarker.source_commit -isnot [string] -or $runtimeMarker.source_commit -cnotmatch '^[0-9a-f]{40}$') {
        throw "AccordLock runtime source commit is missing or malformed."
    }
    if ($runtimeMarker.source_dirty -isnot [bool]) {
        throw "AccordLock runtime source state is missing or malformed."
    }
    if ($runtimeMarker.source_commit -ceq ("0" * 40) -and -not $runtimeMarker.source_dirty) {
        throw "An uncommitted runtime source sentinel cannot identify a clean build."
    }
    if ($runtimeMarker.source_dirty -and -not $AllowDirtyDevelopment) {
        throw "A dirty AccordLock runtime is allowed only for an explicit local development build."
    }
    if ($runtimeMarker.binary -cne "accordlock-agent-runtime.exe") {
        throw "AccordLock runtime marker must declare accordlock-agent-runtime.exe."
    }
    if ($runtimeMarker.binary_sha256 -isnot [string] -or $runtimeMarker.binary_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "AccordLock runtime digest is missing or malformed."
    }
    $runtimeDigest = (Get-FileHash -LiteralPath $runtimeBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($runtimeDigest -cne $runtimeMarker.binary_sha256) {
        throw "AccordLock runtime digest does not match its build marker."
    }

    try {
        $preflightMarker = Get-Content -LiteralPath $preflightMarkerPath -Raw | ConvertFrom-Json
    } catch {
        throw "Invalid deployment preflight runner marker JSON: $($_.Exception.Message)"
    }
    $expectedPreflightFields = @(
        "binary_sha256",
        "component",
        "dirty",
        "protocol_version",
        "schema_version",
        "source_commit"
    ) | Sort-Object
    $actualPreflightFields = @($preflightMarker.PSObject.Properties.Name) | Sort-Object
    if (Compare-Object -ReferenceObject $expectedPreflightFields -DifferenceObject $actualPreflightFields) {
        throw "Deployment preflight runner marker fields are missing or unexpected."
    }
    if (
        $preflightMarker.schema_version -ne 1 -or
        $preflightMarker.component -cne "accordlock-preflight-runner" -or
        $preflightMarker.protocol_version -ne 1
    ) {
        throw "Deployment preflight runner marker identifies an incompatible component."
    }
    if ($preflightMarker.source_commit -isnot [string] -or $preflightMarker.source_commit -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
        throw "Deployment preflight runner source commit is missing or malformed."
    }
    if ($preflightMarker.dirty -isnot [bool]) {
        throw "Deployment preflight runner source state is missing or malformed."
    }
    if ($preflightMarker.source_commit -cmatch '^0+$' -and -not $preflightMarker.dirty) {
        throw "An uncommitted preflight source sentinel cannot identify a clean build."
    }
    if ($preflightMarker.dirty -and -not $AllowDirtyDevelopment) {
        throw "A dirty deployment preflight runner is allowed only for an explicit local development build."
    }
    if (
        $preflightMarker.source_commit -cne $runtimeMarker.source_commit -or
        $preflightMarker.dirty -ne $runtimeMarker.source_dirty
    ) {
        throw "Runtime and deployment preflight artifacts must come from the same source state."
    }
    if ($preflightMarker.binary_sha256 -isnot [string] -or $preflightMarker.binary_sha256 -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw "Deployment preflight runner digest is missing or malformed."
    }
    $preflightDigest = (Get-FileHash -LiteralPath $preflightBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (("sha256:" + $preflightDigest) -cne $preflightMarker.binary_sha256) {
        throw "Deployment preflight runner digest does not match its build marker."
    }

    return [pscustomobject]@{
        BinaryPath = $runtimeBinaryPath
        MarkerPath = $runtimeMarkerPath
        PreflightBinaryPath = $preflightBinaryPath
        PreflightMarkerPath = $preflightMarkerPath
        Commit = $runtimeMarker.source_commit
        Dirty = $runtimeMarker.source_dirty
        Digest = $runtimeDigest
        PreflightDigest = $preflightDigest
    }
}

function Remove-AccordLockRuntimeTempDirectory {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $resolvedDirectory = [System.IO.Path]::GetFullPath($Directory)
    $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (
        $resolvedDirectory -eq $resolvedTempRoot -or
        -not $resolvedDirectory.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Refusing to remove a runtime staging directory outside the OS temporary directory."
    }
    if (Test-Path -LiteralPath $resolvedDirectory) {
        Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force
    }
}

function Remove-AccordLockSquirrelVendorTempDirectory {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $resolvedDirectory = [System.IO.Path]::GetFullPath($Directory)
    $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $leafName = Split-Path -Leaf $resolvedDirectory
    if (
        -not $resolvedDirectory.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $leafName.StartsWith('accordlock-squirrel-vendor-', [System.StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove a Squirrel vendor directory outside the expected temporary path."
    }
    if (Test-Path -LiteralPath $resolvedDirectory) {
        $item = Get-Item -LiteralPath $resolvedDirectory -Force
        if (
            -not $item.PSIsContainer -or
            -not [string]::IsNullOrEmpty($item.LinkType) -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        ) {
            throw "Refusing to remove a non-regular Squirrel vendor staging directory."
        }
        Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force
    }
}

Write-Host "=== AccordLock Windows Build Script ===" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

$missing = @()
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) { $missing += "Rust (install from https://rustup.rs)" }
if (-not (Get-Command "node" -ErrorAction SilentlyContinue)) { $missing += "Node.js v24+ (install from https://nodejs.org)" }
if (-not (Get-Command "corepack" -ErrorAction SilentlyContinue)) { $missing += "Corepack (enable it from your Node.js installation)" }
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) { $missing += "Git (install from https://git-scm.com)" }

if ($missing.Count -gt 0) {
    Write-Host "Missing prerequisites:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "  - $m" -ForegroundColor Red
    }
    exit 1
}

$cargoVersion = (cargo --version).Trim()
$nodeVersion = (node --version).Trim()
$corepackVersion = (corepack --version).Trim()
Push-Location "ui"
try {
    $pnpmVersion = (corepack pnpm --version).Trim()
} finally {
    Pop-Location
}
Assert-MinimumToolVersion -Tool "Node.js" -RawVersion $nodeVersion -MinimumVersion ([version]"24.10.0")
$minimumCorepackVersion = if ($PrepareOnly) {
    # PrepareOnly never installs packages or creates a distributable artifact.
    # Corepack 0.31 can resolve the pinned pnpm version used for this local path.
    [version]"0.31.0"
} else {
    [version]"0.34.0"
}
Assert-MinimumToolVersion -Tool "Corepack" -RawVersion $corepackVersion -MinimumVersion $minimumCorepackVersion
Assert-MinimumToolVersion -Tool "pnpm" -RawVersion $pnpmVersion -MinimumVersion ([version]"10.30.0")
Write-Host "  cargo: $cargoVersion" -ForegroundColor Green
Write-Host "  node:  $nodeVersion" -ForegroundColor Green
Write-Host "  corepack: $corepackVersion" -ForegroundColor Green
Write-Host "  pnpm:  $pnpmVersion" -ForegroundColor Green
Write-Host ""

$sourceIdentity = Resolve-AccordLockSourceIdentity `
    -Repository (Get-Location).Path `
    -Component "Goose" `
    -AllowUncommittedDevelopment ($developmentMode -and $AllowDirty)
$sourceCommit = $sourceIdentity.Commit
$sourceDirty = $sourceIdentity.Dirty
if ($Release -and $sourceCommit -cne $releaseLock.components.accordlock_goose_distribution.commit) {
    throw "The Goose source commit does not match the validated release lock."
}
if ($sourceDirty -and -not ($developmentMode -and $AllowDirty)) {
    throw "Dirty AccordLock source requires -Development -AllowDirty and ACCORDLOCK_ALLOW_DIRTY_BUILD=1."
}

# Step 1: Build the protected backend. Packaged development builds are still
# distributable artifacts, so never embed debug symbols or machine-local source
# paths in their protected sidecars.
if ($ResumeFromVerifiedDesktopBinaries) {
    Write-Host "[2-3/6] Verifying staged native binaries for desktop resume..." -ForegroundColor Yellow
    $binDir = "ui\desktop\src\bin"
    $requiredStagedFiles = @(
        "goose.exe",
        "accordlock-build.json",
        "accordlock-agent-runtime.exe",
        "accordlock-runtime-build.json",
        "accordlock-preflight-runner.exe",
        "accordlock-preflight-runner-build.json"
    )
    foreach ($requiredStagedFile in $requiredStagedFiles) {
        $requiredStagedPath = Join-Path $binDir $requiredStagedFile
        $requiredStagedItem = Get-Item -LiteralPath $requiredStagedPath -ErrorAction Stop
        if ($requiredStagedItem.PSIsContainer -or -not [string]::IsNullOrEmpty($requiredStagedItem.LinkType)) {
            throw "Staged native artifact must be one regular non-link file: $requiredStagedPath"
        }
    }
    Assert-AccordLockBinaryPathHygiene `
        -BinaryPath (Join-Path $binDir 'goose.exe') `
        -SourceRoot (Get-Location).Path

    Push-Location "ui\desktop"
    try {
        node scripts/verify-accordlock-backend.js
        if ($LASTEXITCODE -ne 0) {
            throw "Staged native binary verification failed; rebuild stages 2-3."
        }
    } finally {
        Pop-Location
    }

    $stagedGooseMarker = Get-Content -LiteralPath (Join-Path $binDir "accordlock-build.json") -Raw | ConvertFrom-Json
    if (
        $stagedGooseMarker.source_commit -cne $sourceCommit -or
        $stagedGooseMarker.source_dirty -ne $sourceDirty
    ) {
        throw "Staged Goose binary does not match the current source identity and dirty state."
    }

    $resolvedRuntimeRepo = (Resolve-Path -LiteralPath $RuntimeRepo -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedRuntimeRepo "Cargo.toml") -PathType Leaf)) {
        throw "Runtime repository is missing Cargo.toml: $resolvedRuntimeRepo"
    }
    $runtimeSourceIdentity = Resolve-AccordLockSourceIdentity `
        -Repository $resolvedRuntimeRepo `
        -Component "AccordLock runtime" `
        -AllowUncommittedDevelopment $true
    $verifiedRuntime = Assert-AccordLockRuntimeArtifacts `
        -Directory $binDir `
        -AllowDirtyDevelopment $true
    Assert-AccordLockBinaryPathHygiene `
        -BinaryPath $verifiedRuntime.BinaryPath `
        -SourceRoot $resolvedRuntimeRepo
    Assert-AccordLockBinaryPathHygiene `
        -BinaryPath $verifiedRuntime.PreflightBinaryPath `
        -SourceRoot $resolvedRuntimeRepo
    if (
        $verifiedRuntime.Commit -cne $runtimeSourceIdentity.Commit -or
        $verifiedRuntime.Dirty -ne $runtimeSourceIdentity.Dirty
    ) {
        throw "Staged runtime binaries do not match the current runtime source identity and dirty state."
    }
    Write-Host "  Reusing verified Goose $($sourceCommit.Substring(0, 12)) and runtime $($verifiedRuntime.Commit.Substring(0, 12))." -ForegroundColor Green
    Write-Host ""
} else {
    $profileName = "release"
    Write-Host "[2/6] Building Rust backend ($profileName)..." -ForegroundColor Yellow
$gooseCargoArguments = @(
    "build",
    "--locked",
    "--release",
    "-p", "goose-cli",
    "--bin", "goose",
    "--no-default-features",
    "--features", "accordlock-distribution,rustls-tls,system-keyring"
)
$gooseBuildExitCode = 1
Invoke-AccordLockCargoBuild `
    -Arguments $gooseCargoArguments `
    -SourceRoot (Get-Location).Path `
    -NativePackagesToClean @('aws-lc-sys') `
    -ExitCode ([ref]$gooseBuildExitCode)
if ($gooseBuildExitCode -ne 0) {
    Write-Host "Rust build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Rust build complete." -ForegroundColor Green
Write-Host ""

# Step 2: Copy binaries
Write-Host "[3/6] Copying binaries to desktop app..." -ForegroundColor Yellow
$binDir = "ui\desktop\src\bin"
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }

$gooseBinary = "target\$profileName\goose.exe"
if (-not (Test-Path $gooseBinary)) {
    Write-Host "Backend binary not found: $gooseBinary" -ForegroundColor Red
    exit 1
}
Assert-AccordLockBinaryPathHygiene `
    -BinaryPath $gooseBinary `
    -SourceRoot (Get-Location).Path
Copy-Item $gooseBinary "$binDir\" -Force
$stagedBinary = Join-Path $binDir "goose.exe"
$binaryHash = (Get-FileHash -LiteralPath $stagedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceCommit -notmatch '^[0-9a-f]{40}$') {
    Write-Host "Resolved source commit has an invalid format." -ForegroundColor Red
    exit 1
}
$buildMarker = [ordered]@{
    schema_version = 2
    distribution = "AccordLock"
    policy_feature = "accordlock-distribution"
    source_commit = $sourceCommit
    source_dirty = $sourceDirty
    binary = "goose.exe"
    binary_sha256 = $binaryHash
}
$buildMarker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $binDir "accordlock-build.json") -Encoding utf8NoBOM

$runtimeTempDirectory = $null
try {
    if (-not [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
        $resolvedRuntimeRepo = (Resolve-Path -LiteralPath $RuntimeRepo -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath (Join-Path $resolvedRuntimeRepo "Cargo.toml") -PathType Leaf)) {
            throw "Runtime repository is missing Cargo.toml: $resolvedRuntimeRepo"
        }
        $runtimeSourceIdentity = Resolve-AccordLockSourceIdentity `
            -Repository $resolvedRuntimeRepo `
            -Component "AccordLock runtime" `
            -AllowUncommittedDevelopment ($developmentMode -and $AllowDirty)
        $runtimeSourceCommit = $runtimeSourceIdentity.Commit
        $runtimeSourceDirty = $runtimeSourceIdentity.Dirty
        if ($runtimeSourceDirty -and -not ($developmentMode -and $AllowDirty)) {
            throw "Dirty runtime source requires -Development -AllowDirty and ACCORDLOCK_ALLOW_DIRTY_BUILD=1."
        }

        Write-Host "  Building trusted runtime from explicit repository: $resolvedRuntimeRepo" -ForegroundColor Yellow
        Push-Location $resolvedRuntimeRepo
        try {
            $runtimeCargoArguments = @(
                "build",
                "--locked",
                "--release",
                "-p", "accordlock-agent-runtime",
                "--bin", "accordlock-agent-runtime",
                "-p", "accordlock-preflight-runner",
                "--bin", "accordlock-preflight-runner"
            )
            $runtimeBuildExitCode = 1
            Invoke-AccordLockCargoBuild `
                -Arguments $runtimeCargoArguments `
                -SourceRoot $resolvedRuntimeRepo `
                -NativePackagesToClean @('aws-lc-sys') `
                -ExitCode ([ref]$runtimeBuildExitCode)
            if ($runtimeBuildExitCode -ne 0) {
                throw "AccordLock runtime build failed."
            }
        } finally {
            Pop-Location
        }

        $builtRuntimeBinary = Join-Path $resolvedRuntimeRepo "target\$profileName\accordlock-agent-runtime.exe"
        $builtPreflightBinary = Join-Path $resolvedRuntimeRepo "target\$profileName\accordlock-preflight-runner.exe"
        if (-not (Test-Path -LiteralPath $builtRuntimeBinary -PathType Leaf)) {
            throw "Runtime build did not produce the exact binary: $builtRuntimeBinary"
        }
        if (-not (Test-Path -LiteralPath $builtPreflightBinary -PathType Leaf)) {
            throw "Runtime build did not produce the deployment preflight runner: $builtPreflightBinary"
        }
        Assert-AccordLockBinaryPathHygiene `
            -BinaryPath $builtRuntimeBinary `
            -SourceRoot $resolvedRuntimeRepo
        Assert-AccordLockBinaryPathHygiene `
            -BinaryPath $builtPreflightBinary `
            -SourceRoot $resolvedRuntimeRepo
        $runtimeTempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "accordlock-runtime-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $runtimeTempDirectory | Out-Null
        $runtimeTempBinary = Join-Path $runtimeTempDirectory "accordlock-agent-runtime.exe"
        $preflightTempBinary = Join-Path $runtimeTempDirectory "accordlock-preflight-runner.exe"
        Copy-Item -LiteralPath $builtRuntimeBinary -Destination $runtimeTempBinary
        Copy-Item -LiteralPath $builtPreflightBinary -Destination $preflightTempBinary
        $runtimeTempDigest = (Get-FileHash -LiteralPath $runtimeTempBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        $runtimeBuildMarker = [ordered]@{
            schema_version = 2
            distribution = "AccordLock"
            component = "accordlock-agent-runtime"
            protocol_version = 2
            source_commit = $runtimeSourceCommit
            source_dirty = $runtimeSourceDirty
            binary = "accordlock-agent-runtime.exe"
            binary_sha256 = $runtimeTempDigest
        }
        $runtimeBuildMarker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeTempDirectory "accordlock-runtime-build.json") -Encoding utf8NoBOM
        $preflightTempDigest = (Get-FileHash -LiteralPath $preflightTempBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        $preflightBuildMarker = [ordered]@{
            schema_version = 1
            component = "accordlock-preflight-runner"
            protocol_version = 1
            binary_sha256 = "sha256:$preflightTempDigest"
            source_commit = $runtimeSourceCommit
            dirty = $runtimeSourceDirty
        }
        $preflightBuildMarker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeTempDirectory "accordlock-preflight-runner-build.json") -Encoding utf8NoBOM
        $runtimeArtifactSource = $runtimeTempDirectory
    } else {
        $runtimeArtifactSource = $RuntimeArtifactsDirectory
    }

    $verifiedRuntime = Assert-AccordLockRuntimeArtifacts `
        -Directory $runtimeArtifactSource `
        -AllowDirtyDevelopment ($developmentMode -and $AllowDirty)
    if ($Release -and $verifiedRuntime.Commit -cne $releaseLock.components.accordlock_core.commit) {
        throw "The runtime source commit does not match the validated release lock."
    }
    $stagedRuntimeBinary = Join-Path $binDir "accordlock-agent-runtime.exe"
    $stagedRuntimeMarker = Join-Path $binDir "accordlock-runtime-build.json"
    $stagedPreflightBinary = Join-Path $binDir "accordlock-preflight-runner.exe"
    $stagedPreflightMarker = Join-Path $binDir "accordlock-preflight-runner-build.json"
    foreach ($stagedRuntimeFile in @($stagedRuntimeBinary, $stagedRuntimeMarker, $stagedPreflightBinary, $stagedPreflightMarker)) {
        if (Test-Path -LiteralPath $stagedRuntimeFile) {
            Remove-Item -LiteralPath $stagedRuntimeFile -Force
        }
    }
    Copy-Item -LiteralPath $verifiedRuntime.BinaryPath -Destination $stagedRuntimeBinary
    Copy-Item -LiteralPath $verifiedRuntime.MarkerPath -Destination $stagedRuntimeMarker
    Copy-Item -LiteralPath $verifiedRuntime.PreflightBinaryPath -Destination $stagedPreflightBinary
    Copy-Item -LiteralPath $verifiedRuntime.PreflightMarkerPath -Destination $stagedPreflightMarker
    Write-Host "  Trusted runtime and deployment preflight runner staged at $($verifiedRuntime.Commit.Substring(0, 12))" -ForegroundColor Green
} finally {
    if ($runtimeTempDirectory) {
        Remove-AccordLockRuntimeTempDirectory -Directory $runtimeTempDirectory
    }
}

# Copy required DLLs if they exist (from cross-compilation)
Get-ChildItem "target\$profileName\*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item $_.FullName "$binDir\" -Force
}
Write-Host "  Binaries copied." -ForegroundColor Green
Write-Host ""

if ($developmentMode) {
    Push-Location "ui\desktop"
    try {
        node scripts/verify-accordlock-backend.js
        if ($LASTEXITCODE -ne 0) {
            throw "Development binary verification failed."
        }
    } finally {
        Pop-Location
    }
    if ($PrepareOnly) {
        Write-Host "=== Development binaries prepared ===" -ForegroundColor Cyan
        Write-Host "No dependencies were installed and no package was created."
        Write-Host "Start the UI with: corepack pnpm --dir ui/desktop run start-gui"
        exit 0
    }
}
}

# Step 3: Install npm dependencies
Write-Host "[4/6] Installing desktop dependencies..." -ForegroundColor Yellow
Push-Location "ui\desktop"
try {
    $previousCi = [Environment]::GetEnvironmentVariable('CI', 'Process')
    [Environment]::SetEnvironmentVariable('CI', 'true', 'Process')
    # A build may run under a constrained CI identity while the pnpm store was
    # populated by another Windows account. Copying prevents store hard links
    # from carrying undeletable ACLs into the workspace on subsequent builds.
    corepack pnpm install --frozen-lockfile --package-import-method=copy
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Desktop dependency installation failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    [Environment]::SetEnvironmentVariable('CI', $previousCi, 'Process')
}
Write-Host "  Dependencies installed." -ForegroundColor Green
Write-Host ""

if ($Release) {
    Write-Host "  Signing protected sidecars before desktop compilation..." -ForegroundColor Yellow
    try {
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_FILE', $releaseCertificateFile, 'Process')
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_PASSWORD', $releaseCertificatePassword, 'Process')
        node scripts/sign-accordlock-windows-sidecars.js
        if ($LASTEXITCODE -ne 0) {
            throw "Protected sidecar signing failed."
        }
    } finally {
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_FILE', $null, 'Process')
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_PASSWORD', $null, 'Process')
    }

    node scripts/verify-accordlock-backend.js
    if ($LASTEXITCODE -ne 0) {
        throw "Signed sidecar marker verification failed."
    }
    $binaryHash = (Get-FileHash -LiteralPath (Join-Path (Get-Location) "src\bin\goose.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    $verifiedRuntime.Digest = (Get-FileHash -LiteralPath (Join-Path (Get-Location) "src\bin\accordlock-agent-runtime.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    $verifiedRuntime.PreflightDigest = (Get-FileHash -LiteralPath (Join-Path (Get-Location) "src\bin\accordlock-preflight-runner.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "  Sidecars signed and final digests recorded before Vite compilation." -ForegroundColor Green
    Write-Host ""
}

# Step 4: Prepare platform binaries and build desktop assets
Write-Host "[5/6] Preparing Windows binaries and desktop assets..." -ForegroundColor Yellow
node scripts/prepare-platform-binaries.js
if ($LASTEXITCODE -ne 0) {
    Write-Host "Windows support binary preparation failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
node scripts/sanitize-windows-build-paths.js --uv (Join-Path (Get-Location).Path 'src\bin\uv.exe')
if ($LASTEXITCODE -ne 0) {
    throw "Windows support binary path sanitization failed."
}
corepack pnpm run build-goose-sdk
if ($LASTEXITCODE -ne 0) {
    Write-Host "Goose SDK build or Vite cache cleanup failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
corepack pnpm run i18n:compile
if ($LASTEXITCODE -ne 0) {
    Write-Host "i18n compilation failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Write-Host "  Desktop assets built." -ForegroundColor Green
Write-Host ""

node scripts/verify-accordlock-backend.js
if ($LASTEXITCODE -ne 0) {
    Write-Host "Protected backend verification failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Step 5: Package once and make the installer/artifacts
Write-Host "[6/6] Packaging AccordLock and creating Windows artifacts..." -ForegroundColor Yellow
$previousSquirrelVendorDirectory = [Environment]::GetEnvironmentVariable(
    'ACCORDLOCK_SQUIRREL_VENDOR_DIRECTORY',
    'Process'
)
$squirrelVendorTempRoot = $null
try {
    if ($Release) {
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_FILE', $releaseCertificateFile, 'Process')
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_PASSWORD', $releaseCertificatePassword, 'Process')
    }
    # The workspace CLI is hoisted under ui/node_modules. Address its pinned
    # entry point directly so packaging does not depend on pnpm's cwd-specific
    # executable lookup or on a globally installed electron-forge command.
    $electronForgeCli = Join-Path `
        (Split-Path -Parent (Get-Location).Path) `
        'node_modules\@electron-forge\cli\dist\electron-forge.js'
    if (-not (Test-Path -LiteralPath $electronForgeCli -PathType Leaf)) {
        throw "The pinned Electron Forge CLI is missing: $electronForgeCli"
    }

    $electronWinstallerVendor = Join-Path `
        (Split-Path -Parent (Get-Location).Path) `
        'node_modules\electron-winstaller\vendor'
    $electronWinstallerVendorItem = Get-Item -LiteralPath $electronWinstallerVendor -Force -ErrorAction Stop
    if (
        -not $electronWinstallerVendorItem.PSIsContainer -or
        -not [string]::IsNullOrEmpty($electronWinstallerVendorItem.LinkType) -or
        (($electronWinstallerVendorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    ) {
        throw "The pinned electron-winstaller vendor directory must be one regular non-link directory."
    }
    $squirrelVendorTempRoot = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        "accordlock-squirrel-vendor-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $squirrelVendorTempRoot | Out-Null
    $squirrelVendorDirectory = Join-Path $squirrelVendorTempRoot 'vendor'
    Copy-Item -LiteralPath $electronWinstallerVendor -Destination $squirrelVendorDirectory -Recurse
    $stagedNuGet = Join-Path $squirrelVendorDirectory 'nuget.exe'
    Copy-Item -LiteralPath $nuGetExecutable -Destination $stagedNuGet -Force
    $stagedNuGetDigest = (Get-FileHash -LiteralPath $stagedNuGet -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($stagedNuGetDigest -cne $expectedNuGetBinarySha256) {
        throw "The staged NuGet tool does not match the repository checksum pin."
    }
    $stagedSquirrelSetup = Join-Path $squirrelVendorDirectory 'Setup.exe'
    node scripts/sanitize-windows-build-paths.js --squirrel-stub $stagedSquirrelSetup
    if ($LASTEXITCODE -ne 0) {
        throw "Squirrel installer-stub path sanitization failed."
    }
    [Environment]::SetEnvironmentVariable(
        'ACCORDLOCK_SQUIRREL_VENDOR_DIRECTORY',
        $squirrelVendorDirectory,
        'Process'
    )

    node $electronForgeCli package --platform win32 --arch x64
    if ($LASTEXITCODE -ne 0) {
        throw "Package failed; refusing to report a partial installer set as complete."
    }
    foreach ($makerTarget in @('@electron-forge/maker-squirrel', '@electron-forge/maker-zip')) {
        # Forge otherwise runs makers concurrently. Squirrel and ZIP both read
        # the large protected sidecars, and electron-winstaller can close a
        # shared stream while the ZIP maker is still consuming it. Run each
        # pinned maker against the same completed package, in a fixed order.
        node $electronForgeCli make `
            --skip-package `
            --platform win32 `
            --arch x64 `
            --targets $makerTarget
        if ($LASTEXITCODE -ne 0) {
            throw "Maker '$makerTarget' failed; refusing to report a partial installer set as complete."
        }
    }
} finally {
    [Environment]::SetEnvironmentVariable(
        'ACCORDLOCK_SQUIRREL_VENDOR_DIRECTORY',
        $previousSquirrelVendorDirectory,
        'Process'
    )
    if ($squirrelVendorTempRoot) {
        Remove-AccordLockSquirrelVendorTempDirectory -Directory $squirrelVendorTempRoot
    }
    if ($Release) {
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_FILE', $null, 'Process')
        [Environment]::SetEnvironmentVariable('WINDOWS_CERTIFICATE_PASSWORD', $null, 'Process')
    }
}
Pop-Location
Write-Host ""

$desktopOutputRoot = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) "ui\desktop\out"))
$packagedApplicationRoot = Join-Path $desktopOutputRoot "AccordLock-win32-x64"
$knownSbomPaths = @(
    Join-Path $desktopOutputRoot 'accordlock-desktop.cdx.json'
    Join-Path $desktopOutputRoot 'accordlock-goose-source.cdx.json'
    Join-Path $desktopOutputRoot 'accordlock-core-source.cdx.json'
)
foreach ($staleSbomPath in $knownSbomPaths) {
    if (-not (Test-Path -LiteralPath $staleSbomPath)) {
        continue
    }
    $staleSbomItem = Get-Item -LiteralPath $staleSbomPath -Force
    if ($staleSbomItem.PSIsContainer -or
        -not [string]::IsNullOrEmpty($staleSbomItem.LinkType) -or
        (($staleSbomItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Refusing to replace a non-regular SBOM path: $staleSbomPath"
    }
    Remove-Item -LiteralPath $staleSbomPath -Force
}
$generatedSbomPaths = @()
if ($syftExecutable) {
    $sbomArguments = @(
        '-NoProfile',
        '-File', $sbomGenerationScript,
        '-SyftToolPath', $syftExecutable,
        '-DesktopOutputRoot', $desktopOutputRoot,
        '-GooseRoot', (Get-Location).Path,
        '-GooseCommit', $sourceCommit
    )
    if (-not [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
        $sbomArguments += @(
            '-RuntimeRepo', $resolvedRuntimeRepo,
            '-RuntimeCommit', $verifiedRuntime.Commit
        )
    }
    if ($Release) {
        $sbomArguments += '-RequireRuntimeSource'
    }
    & pwsh @sbomArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Offline release SBOM generation failed."
    }
    $generatedSbomPaths = @(
        Join-Path $desktopOutputRoot 'accordlock-desktop.cdx.json'
        Join-Path $desktopOutputRoot 'accordlock-goose-source.cdx.json'
    )
    if (-not [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
        $generatedSbomPaths += Join-Path $desktopOutputRoot 'accordlock-core-source.cdx.json'
    }
} elseif ($Development) {
    Write-Warning "Syft $expectedSyftVersion is not available; this local development package has no SBOM."
}

# Record the exact distributable bytes after Forge and any configured code
# signing have completed. The manifest intentionally contains no machine path,
# username, credential, or wall-clock value.
$artifactCandidates = @()
$makeOutputRoot = Join-Path $desktopOutputRoot "make"
if (Test-Path -LiteralPath $makeOutputRoot -PathType Container) {
    $artifactCandidates += Get-ChildItem -LiteralPath $makeOutputRoot -File -Recurse
}
if (Test-Path -LiteralPath $packagedApplicationRoot -PathType Container) {
    $packagedEntries = @(Get-ChildItem -LiteralPath $packagedApplicationRoot -Recurse -Force)
    $unsafePackagedEntries = @($packagedEntries | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($unsafePackagedEntries.Count -gt 0) {
        throw "The packaged application contains a reparse point; refusing an incomplete artifact manifest."
    }
    $artifactCandidates += @($packagedEntries | Where-Object { -not $_.PSIsContainer })
}
foreach ($sbomPath in $generatedSbomPaths) {
    $artifactCandidates += Get-Item -LiteralPath $sbomPath -ErrorAction Stop
}
$artifactCandidates = @($artifactCandidates | Sort-Object FullName -Unique)
if ($artifactCandidates.Count -eq 0) {
    throw "Packaging completed without any distributable artifact to attest."
}

$artifactRecords = @($artifactCandidates | ForEach-Object {
    $relativePath = [System.IO.Path]::GetRelativePath($desktopOutputRoot, $_.FullName).Replace("\", "/")
    [ordered]@{
        path = $relativePath
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size_bytes = $_.Length
    }
})
$finalGooseMarker = Get-Content -LiteralPath (Join-Path (Get-Location) 'ui\desktop\src\bin\accordlock-build.json') -Raw | ConvertFrom-Json
$finalRuntimeMarker = Get-Content -LiteralPath (Join-Path (Get-Location) 'ui\desktop\src\bin\accordlock-runtime-build.json') -Raw | ConvertFrom-Json
$finalPreflightMarker = Get-Content -LiteralPath (Join-Path (Get-Location) 'ui\desktop\src\bin\accordlock-preflight-runner-build.json') -Raw | ConvertFrom-Json
if ($finalGooseMarker.source_commit -cne $sourceCommit -or
    $finalRuntimeMarker.source_commit -cne $verifiedRuntime.Commit -or
    $finalPreflightMarker.source_commit -cne $verifiedRuntime.Commit -or
    $finalGooseMarker.binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $finalRuntimeMarker.binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $finalPreflightMarker.binary_sha256 -cnotmatch '^sha256:[0-9a-f]{64}$') {
    throw "Final sidecar markers do not match the attested source identities."
}
$artifactManifest = [ordered]@{
    schema_version = 1
    distribution = "AccordLock"
    build_kind = if ($Release) { "release" } else { "development" }
    source = [ordered]@{
        goose_commit = $sourceCommit
        goose_dirty = $sourceDirty
        goose_binary_sha256 = $finalGooseMarker.binary_sha256
        runtime_commit = $verifiedRuntime.Commit
        runtime_dirty = $verifiedRuntime.Dirty
        runtime_binary_sha256 = $finalRuntimeMarker.binary_sha256
        preflight_commit = $verifiedRuntime.Commit
        preflight_dirty = $verifiedRuntime.Dirty
        preflight_binary_sha256 = $finalPreflightMarker.binary_sha256
    }
    artifacts = $artifactRecords
}
$artifactManifestPath = Join-Path $desktopOutputRoot "accordlock-artifact-manifest.json"
$artifactManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $artifactManifestPath -Encoding utf8NoBOM
$checksumRecords = @($artifactRecords) + [pscustomobject]@{
    path = 'accordlock-artifact-manifest.json'
    sha256 = (Get-FileHash -LiteralPath $artifactManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes = (Get-Item -LiteralPath $artifactManifestPath).Length
}
$checksumRecords |
    Sort-Object { [string]$_.path } |
    ForEach-Object { "$($_.sha256)  $($_.path)" } |
    Set-Content -LiteralPath (Join-Path $desktopOutputRoot "SHA256SUMS") -Encoding ascii

# Done
if (-not $Release) {
    Write-Host "=== Unsigned Development Build Complete ===" -ForegroundColor Cyan
    Write-Warning "This installer is for local evaluation only. It is not a signed AccordLock release."
} else {
    Write-Host "=== Release Build Complete ===" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Packaged app:  ui\desktop\out\AccordLock-win32-x64\AccordLock.exe" -ForegroundColor Green
Write-Host "Installer:     ui\desktop\out\make\" -ForegroundColor Green
Write-Host "Checksums:     ui\desktop\out\SHA256SUMS" -ForegroundColor Green
Write-Host "Manifest:      ui\desktop\out\accordlock-artifact-manifest.json" -ForegroundColor Green
if ($syftExecutable) {
    Write-Host "SBOMs:         ui\desktop\out\accordlock-*.cdx.json" -ForegroundColor Green
}
Write-Host ""
Write-Host "To run the app directly:" -ForegroundColor Yellow
Write-Host "  .\ui\desktop\out\AccordLock-win32-x64\AccordLock.exe"
Write-Host ""
Write-Host "To install, find the .exe installer in ui\desktop\out\make\"
