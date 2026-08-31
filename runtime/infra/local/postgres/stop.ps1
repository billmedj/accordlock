[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'postgres-common.ps1')

$versionFile = Join-Path $script:AccordLockPostgresData 'PG_VERSION'
if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    Write-Output "NOT_RUNNING postgres_stop reason=no_local_cluster path=$script:AccordLockPostgresData"
    exit 0
}

$pgCtl = Find-AccordLockPostgresCommand -Name 'pg_ctl'
$ready = Test-AccordLockPostgresReady
$postmasterAlive = Test-AccordLockPostmasterAlive
if ($ready -and -not (Test-AccordLockOwnedPostgresServer)) {
    $servingData = Get-AccordLockServingDataDirectory
    throw "Refusing to stop PostgreSQL on port $script:AccordLockPostgresPort because it serves another data directory: $servingData"
}
if (-not $ready) {
    if ($postmasterAlive) {
        throw 'The project PID file names a live process but the dedicated database is not reachable; refusing to signal an unverified PID'
    }
    Write-Output "NOT_RUNNING postgres_stop reason=server_already_stopped path=$script:AccordLockPostgresData"
    exit 0
}

Invoke-AccordLockNative -Command $pgCtl -Arguments @(
    'stop',
    '-D', $script:AccordLockPostgresData,
    '-m', 'fast',
    '-w',
    '-t', '30'
)
if (Test-AccordLockPostgresReady) {
    throw "PostgreSQL still accepts connections on port $script:AccordLockPostgresPort after stop"
}
if (Test-AccordLockPostmasterAlive) {
    throw 'Project PostgreSQL postmaster process remains alive after stop'
}
Write-Output "PASS postgres_stop path=$script:AccordLockPostgresData"
# `pg_isready` intentionally returns a non-zero native exit code after a
# successful stop. Do not leak that expected probe result as this script's
# process status.
exit 0
