#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$SyftToolPath,
    [string]$SyftArchivePath,
    [Parameter(Mandatory)][string]$DesktopOutputRoot,
    [string]$PackagedAppRoot,
    [Parameter(Mandatory)][string]$GooseRoot,
    [string]$RuntimeRepo,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GooseCommit,
    [string]$RuntimeCommit,
    [switch]$RequireRuntimeSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedSyftVersion = '1.51.0'
$ExpectedSyftSha256 = '75adfff66c266adac51fe8addeca97702f82b4d822d02bf70b79f556c84d3a46'
$ExpectedSyftMacArchives = @{
    arm64 = '4f37f4c7fefce0a68e4cf71ba3f5f9829a99e65d89b29f7ee41b8c2c10ea8c59'
    x86_64 = 'cddf9a044145caf0a1a3194d00d1dd51a1666f4814f2919cdb4768a0c062ad95'
}
$ConfigurationPath = Join-Path $PSScriptRoot 'syft-release.yaml'

function Assert-RegularNonLinkFile {
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

function Assert-CycloneDxInventory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$InventoryName,
        [string[]]$RequiredComponentNames = @()
    )

    $item = Assert-RegularNonLinkFile -Path $Path -Description $InventoryName
    if ($item.Length -le 0) {
        throw "$InventoryName is empty."
    }
    $raw = Get-Content -LiteralPath $item.FullName -Raw
    try {
        $bom = $raw | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "$InventoryName is not valid JSON: $($_.Exception.Message)"
    }
    $components = @($bom.components)
    if ($bom.bomFormat -cne 'CycloneDX' -or $components.Count -lt 1) {
        throw "$InventoryName does not contain a CycloneDX component inventory."
    }
    $componentNames = @($components | ForEach-Object { [string]$_.name })
    foreach ($requiredName in $RequiredComponentNames) {
        if ($requiredName -cnotin $componentNames) {
            throw "$InventoryName is missing the required source component '$requiredName'."
        }
    }
}

function Normalize-CycloneDxInventory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SourceName,
        [Parameter(Mandatory)][string]$SourceVersion
    )

    try {
        $bom = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "Generated SBOM is not valid JSON: $($_.Exception.Message)"
    }

    # Syft emits a random UUID and the scan wall clock. Replace those two
    # non-semantic values so identical source and tool inputs yield identical
    # CycloneDX bytes. UUID version 8 is reserved for application-defined data.
    $identityBytes = [Text.Encoding]::UTF8.GetBytes("$SourceName`n$SourceVersion")
    $identityHex = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($identityBytes)
    ).ToLowerInvariant().Substring(0, 32).ToCharArray()
    $identityHex[12] = '8'
    $variantIndex = [Convert]::ToInt32([string]$identityHex[16], 16) -band 3
    $identityHex[16] = '89ab'[$variantIndex]
    $uuidHex = -join $identityHex
    $bom.serialNumber = 'urn:uuid:{0}-{1}-{2}-{3}-{4}' -f `
        $uuidHex.Substring(0, 8),
        $uuidHex.Substring(8, 4),
        $uuidHex.Substring(12, 4),
        $uuidHex.Substring(16, 4),
        $uuidHex.Substring(20, 12)
    if ($null -ne $bom.metadata) {
        $bom.metadata.PSObject.Properties.Remove('timestamp')
    }
    $bom | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Invoke-SyftScan {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$SourceName,
        [Parameter(Mandatory)][string]$SourceVersion,
        [Parameter(Mandatory)][string]$OutputPath,
        [string[]]$Exclusions = @()
    )

    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Force
    }
    $arguments = @(
        'scan',
        "dir:$SourceRoot",
        '--config', $ConfigurationPath,
        '--source-name', $SourceName,
        '--source-version', $SourceVersion
    )
    foreach ($exclusion in $Exclusions) {
        $arguments += @('--exclude', $exclusion)
    }
    $arguments += @('-o', "cyclonedx-json=$OutputPath")
    & $script:SyftExecutable @arguments
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "Syft failed to generate $SourceName."
    }
    Normalize-CycloneDxInventory `
        -Path $OutputPath `
        -SourceName $SourceName `
        -SourceVersion $SourceVersion
}

$syftTemporaryRoot = $null
trap {
    if ($null -ne $syftTemporaryRoot -and (Test-Path -LiteralPath $syftTemporaryRoot)) {
        $resolvedTemporaryRoot = [IO.Path]::GetFullPath($syftTemporaryRoot)
        $temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if ($resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
        }
    }
    throw
}
if ([string]::IsNullOrWhiteSpace($SyftToolPath) -eq [string]::IsNullOrWhiteSpace($SyftArchivePath)) {
    throw 'Specify exactly one pinned Syft input: -SyftToolPath or -SyftArchivePath.'
}
if (-not [string]::IsNullOrWhiteSpace($SyftArchivePath)) {
    if (-not $IsMacOS) {
        throw 'The pinned Syft archive input is supported only by the macOS release path.'
    }
    $archive = Assert-RegularNonLinkFile -Path $SyftArchivePath -Description 'The Syft release archive'
    $hostArchitecture = (& /usr/bin/uname -m).Trim()
    if ($hostArchitecture -cnotin @('arm64', 'x86_64')) {
        throw "Unsupported macOS build-host architecture '$hostArchitecture'."
    }
    $archiveDigest = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($archiveDigest -cne $ExpectedSyftMacArchives[$hostArchitecture]) {
        throw "The Syft $ExpectedSyftVersion $hostArchitecture archive does not match its repository pin."
    }
    $syftTemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "accordlock-syft-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $syftTemporaryRoot | Out-Null
    & /usr/bin/tar -xzf $archive.FullName -C $syftTemporaryRoot syft
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the pinned Syft executable.'
    }
    $SyftExecutable = (Assert-RegularNonLinkFile -Path (Join-Path $syftTemporaryRoot 'syft') -Description 'The extracted Syft executable').FullName
    & /bin/chmod 700 $SyftExecutable
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restrict the extracted Syft executable.'
    }
}
else {
    $SyftExecutable = (Assert-RegularNonLinkFile -Path $SyftToolPath -Description 'The SBOM tool').FullName
    $syftDigest = (Get-FileHash -LiteralPath $SyftExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($syftDigest -cne $ExpectedSyftSha256) {
        throw 'The SBOM tool binary does not match the repository checksum pin.'
    }
}
$null = Assert-RegularNonLinkFile -Path $ConfigurationPath -Description 'The offline SBOM configuration'

$ResolvedDesktopOutputRoot = [IO.Path]::GetFullPath($DesktopOutputRoot)
$ResolvedGooseRoot = (Resolve-Path -LiteralPath $GooseRoot -ErrorAction Stop).Path
$PackagedApplicationRoot = if ([string]::IsNullOrWhiteSpace($PackagedAppRoot)) {
    Join-Path $ResolvedDesktopOutputRoot 'AccordLock-win32-x64'
}
else {
    [IO.Path]::GetFullPath($PackagedAppRoot)
}
$outputPrefix = $ResolvedDesktopOutputRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $PackagedApplicationRoot.StartsWith($outputPrefix, [StringComparison]::Ordinal)) {
    throw 'The packaged application must be inside the declared desktop output root.'
}
if (-not (Test-Path -LiteralPath $PackagedApplicationRoot -PathType Container)) {
    throw 'The packaged application directory is missing; refusing to generate an empty SBOM.'
}
New-Item -ItemType Directory -Force -Path $ResolvedDesktopOutputRoot | Out-Null

$ResolvedRuntimeRepo = $null
if (-not [string]::IsNullOrWhiteSpace($RuntimeRepo)) {
    $ResolvedRuntimeRepo = (Resolve-Path -LiteralPath $RuntimeRepo -ErrorAction Stop).Path
    if ($RuntimeCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'A runtime source SBOM requires its exact 40-character source commit.'
    }
}
elseif ($RequireRuntimeSource) {
    throw 'Release SBOM generation requires the AccordLock runtime source repository.'
}

$DesktopSbomPath = Join-Path $ResolvedDesktopOutputRoot 'accordlock-desktop.cdx.json'
$GooseSbomPath = Join-Path $ResolvedDesktopOutputRoot 'accordlock-goose-source.cdx.json'
$CoreSbomPath = Join-Path $ResolvedDesktopOutputRoot 'accordlock-core-source.cdx.json'

# Syft configuration may be changed by environment variables. Remove every
# SYFT_* override for the duration of this offline, repository-controlled scan.
$savedSyftEnvironment = @{}
foreach ($entry in Get-ChildItem Env:) {
    if ($entry.Name.StartsWith('SYFT_', [StringComparison]::OrdinalIgnoreCase)) {
        $savedSyftEnvironment[$entry.Name] = $entry.Value
        [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
    }
}

try {
    $versionJson = (& $SyftExecutable version -o json --config $ConfigurationPath) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not query the SBOM tool version.'
    }
    try {
        $actualVersion = ($versionJson | ConvertFrom-Json).version
    }
    catch {
        throw 'The SBOM tool did not return valid version JSON.'
    }
    if ($actualVersion -cne $ExpectedSyftVersion) {
        throw "SBOM generation requires Syft $ExpectedSyftVersion; found '$actualVersion'."
    }

    Invoke-SyftScan `
        -SourceRoot $PackagedApplicationRoot `
        -SourceName 'AccordLock Desktop' `
        -SourceVersion $GooseCommit `
        -OutputPath $DesktopSbomPath
    Assert-CycloneDxInventory -Path $DesktopSbomPath -InventoryName 'The packaged-application SBOM'

    Invoke-SyftScan `
        -SourceRoot $ResolvedGooseRoot `
        -SourceName 'AccordLock Goose Source' `
        -SourceVersion $GooseCommit `
        -OutputPath $GooseSbomPath `
        -Exclusions @(
            './.git/**',
            './target/**',
            './ui/node_modules/**',
            './ui/desktop/out/**',
            './ui/desktop/.accordlock-dev-runtime/**',
            './ui/desktop/src/bin/**'
        )
    Assert-CycloneDxInventory `
        -Path $GooseSbomPath `
        -InventoryName 'The Goose source SBOM' `
        -RequiredComponentNames @('goose-cli')

    if ($null -ne $ResolvedRuntimeRepo) {
        Invoke-SyftScan `
            -SourceRoot $ResolvedRuntimeRepo `
            -SourceName 'AccordLock Core Source' `
            -SourceVersion $RuntimeCommit `
            -OutputPath $CoreSbomPath `
            -Exclusions @('./.git/**', './target/**')
        Assert-CycloneDxInventory `
            -Path $CoreSbomPath `
            -InventoryName 'The AccordLock core source SBOM' `
            -RequiredComponentNames @('accordlock-agent-runtime', 'accordlock-preflight-runner')
    }
    elseif (Test-Path -LiteralPath $CoreSbomPath) {
        Remove-Item -LiteralPath $CoreSbomPath -Force
    }
}
finally {
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name.StartsWith('SYFT_', [StringComparison]::OrdinalIgnoreCase)) {
            [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
        }
    }
    foreach ($name in $savedSyftEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedSyftEnvironment[$name], 'Process')
    }
    if ($null -ne $syftTemporaryRoot -and (Test-Path -LiteralPath $syftTemporaryRoot)) {
        $resolvedTemporaryRoot = [IO.Path]::GetFullPath($syftTemporaryRoot)
        $temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::Ordinal)) {
            throw 'Refusing to remove a Syft staging directory outside the operating-system temporary directory.'
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

[pscustomobject]@{
    Desktop = $DesktopSbomPath
    GooseSource = $GooseSbomPath
    CoreSource = if ($null -ne $ResolvedRuntimeRepo) { $CoreSbomPath } else { $null }
}
