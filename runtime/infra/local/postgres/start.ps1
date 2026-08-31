[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'postgres-common.ps1')

& (Join-Path $PSScriptRoot 'init.ps1')
if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL initialization failed with exit code $LASTEXITCODE"
}

$pgCtl = Find-AccordLockPostgresCommand -Name 'pg_ctl'
$alreadyRunning = Test-AccordLockOwnedPostgresServer
if ((Test-AccordLockPostgresReady) -and -not $alreadyRunning) {
    $servingData = Get-AccordLockServingDataDirectory
    throw "Port $script:AccordLockPostgresPort is occupied by a different PostgreSQL data directory: $servingData"
}
if ((Test-AccordLockPostmasterAlive) -and -not $alreadyRunning) {
    throw 'The project postmaster PID exists but its database is not ready; refusing a second start'
}
if (-not $alreadyRunning) {
    New-Item -ItemType Directory -Path $script:AccordLockLocalRoot -Force | Out-Null
    Invoke-AccordLockNative -Command $pgCtl -Arguments @(
        'start',
        '-D', $script:AccordLockPostgresData,
        '-l', $script:AccordLockPostgresLog,
        '-w',
        '-t', '30',
        '-o', "-p $script:AccordLockPostgresPort -h 127.0.0.1"
    )
}

if (-not (Test-AccordLockOwnedPostgresServer)) {
    throw 'PostgreSQL became reachable but does not report the project-local data directory'
}

$psql = Find-AccordLockPostgresCommand -Name 'psql'
$databaseExists = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $script:AccordLockPostgresPort `
    -U $script:AccordLockPostgresUser -d postgres -tA -c `
    "SELECT 1 FROM pg_database WHERE datname = '$script:AccordLockPostgresDatabase'"
if ($LASTEXITCODE -ne 0) {
    throw "Could not query local PostgreSQL with exit code $LASTEXITCODE"
}
if (($databaseExists -join '').Trim() -ne '1') {
    $createdb = Find-AccordLockPostgresCommand -Name 'createdb'
    Invoke-AccordLockNative -Command $createdb -Arguments @(
        '-h', '127.0.0.1',
        '-p', "$script:AccordLockPostgresPort",
        '-U', $script:AccordLockPostgresUser,
        $script:AccordLockPostgresDatabase
    )
}

$state = if ($alreadyRunning) { 'existing_server' } else { 'started_server' }
Write-Output "PASS postgres_start state=$state port=$script:AccordLockPostgresPort database=$script:AccordLockPostgresDatabase"
Write-Output "ACCORDLOCK_TEST_POSTGRES_URL=$script:AccordLockPostgresUrl"
