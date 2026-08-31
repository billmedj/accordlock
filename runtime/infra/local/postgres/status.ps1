[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'postgres-common.ps1')

$versionFile = Join-Path $script:AccordLockPostgresData 'PG_VERSION'
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    Write-Output "NOT_INITIALIZED postgres_status path=$script:AccordLockPostgresData"
    exit 1
}

$ready = Test-AccordLockPostgresReady
if ($ready -and -not (Test-AccordLockOwnedPostgresServer)) {
    $servingData = Get-AccordLockServingDataDirectory
    Write-Error "Port $script:AccordLockPostgresPort serves a different PostgreSQL data directory: $servingData"
}
if (-not $ready) {
    Write-Output "NOT_RUNNING postgres_status path=$script:AccordLockPostgresData"
    exit 1
}
$postmasterPid = Get-AccordLockPostmasterPid
if ($null -eq $postmasterPid -or -not (Test-AccordLockPostmasterAlive)) {
    Write-Error 'PostgreSQL answers on the dedicated port but the project postmaster PID is absent or dead'
}
Write-Output "PASS postgres_status pid=$postmasterPid url=$script:AccordLockPostgresUrl"
