[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$InstallDirectory = Join-Path $RepoRoot '.local\bin'
$Destination = Join-Path $InstallDirectory 'kind.exe'
$Version = 'v0.32.0'
$ExpectedSha256 = '0bcb2d1cfedc1912d664014db716937e8a0e843e91c6807b4db2025dbc8989fa'
$DownloadUrl = "https://github.com/kubernetes-sigs/kind/releases/download/$Version/kind-windows-amd64"

function Get-Sha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null

if (Test-Path -LiteralPath $Destination -PathType Leaf) {
    $ExistingSha256 = Get-Sha256 -Path $Destination
    if ($ExistingSha256 -ne $ExpectedSha256) {
        throw "Refusing to replace existing '$Destination': expected SHA-256 $ExpectedSha256, observed $ExistingSha256."
    }

    $ExistingVersion = (& $Destination version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $ExistingVersion -notmatch ('^kind\s+' + [regex]::Escape($Version) + '(?:\s|$)')) {
        throw "Existing '$Destination' has the reviewed hash but did not report kind $Version."
    }

    Write-Output "kind $Version is already installed at '$Destination'."
    exit 0
}

$Temporary = Join-Path $InstallDirectory ("kind-{0}.download" -f ([Guid]::NewGuid().ToString('N')))
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $Temporary
    $ActualSha256 = Get-Sha256 -Path $Temporary
    if ($ActualSha256 -ne $ExpectedSha256) {
        throw "Downloaded kind checksum mismatch: expected $ExpectedSha256, observed $ActualSha256."
    }

    Move-Item -LiteralPath $Temporary -Destination $Destination
    $InstalledVersion = (& $Destination version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $InstalledVersion -notmatch ('^kind\s+' + [regex]::Escape($Version) + '(?:\s|$)')) {
        throw "Installed binary did not report kind $Version."
    }

    Write-Output "Installed $InstalledVersion at '$Destination'."
    Write-Output "Verified SHA-256: $ExpectedSha256"
}
finally {
    if (Test-Path -LiteralPath $Temporary -PathType Leaf) {
        Remove-Item -LiteralPath $Temporary -Force
    }
}
