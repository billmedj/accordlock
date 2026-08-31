Set-StrictMode -Version Latest

$script:AccordLockPostgresPort = 55432
$script:AccordLockPostgresDatabase = 'accordlock_test_v2'
$script:AccordLockPostgresUser = 'postgres'
$script:AccordLockRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$script:AccordLockLocalRoot = [IO.Path]::GetFullPath((Join-Path $script:AccordLockRepositoryRoot '.local\postgres'))
$script:AccordLockPostgresData = [IO.Path]::GetFullPath((Join-Path $script:AccordLockLocalRoot 'data'))
$script:AccordLockPostgresLog = [IO.Path]::GetFullPath((Join-Path $script:AccordLockLocalRoot 'postgres.log'))
$script:AccordLockPostgresUrl = "postgresql://${script:AccordLockPostgresUser}@127.0.0.1:${script:AccordLockPostgresPort}/${script:AccordLockPostgresDatabase}"

$allowedPrefix = $script:AccordLockLocalRoot.TrimEnd('\') + '\'
if (-not $script:AccordLockPostgresData.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing PostgreSQL path outside project .local directory: $script:AccordLockPostgresData"
}

function Find-AccordLockPostgresCommand {
    param([Parameter(Mandatory)][string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $candidate = Join-Path 'C:\Program Files\PostgreSQL\17\bin' "$Name.exe"
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }
    throw "PostgreSQL command is missing: $Name (expected PostgreSQL 17)"
}

function Invoke-AccordLockNative {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(ValueFromRemainingArguments)][string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code ${LASTEXITCODE}: $Command"
    }
}

function Test-AccordLockPostgresReady {
    $pgIsReady = Find-AccordLockPostgresCommand -Name 'pg_isready'
    & $pgIsReady -h 127.0.0.1 -p $script:AccordLockPostgresPort `
        -U $script:AccordLockPostgresUser -d postgres *> $null
    return $LASTEXITCODE -eq 0
}

function Get-AccordLockPostmasterPid {
    $pidFile = Join-Path $script:AccordLockPostgresData 'postmaster.pid'
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
        return $null
    }
    $firstLine = Get-Content -LiteralPath $pidFile -TotalCount 1
    $parsed = 0
    if (-not [int]::TryParse($firstLine, [ref]$parsed) -or $parsed -le 0) {
        throw "Invalid PostgreSQL postmaster PID file: $pidFile"
    }
    return $parsed
}

function Test-AccordLockPostmasterAlive {
    $postmasterPid = Get-AccordLockPostmasterPid
    if ($null -eq $postmasterPid) {
        return $false
    }
    return $null -ne (Get-Process -Id $postmasterPid -ErrorAction SilentlyContinue)
}

function Get-AccordLockServingDataDirectory {
    if (-not (Test-AccordLockPostgresReady)) {
        return $null
    }
    $psql = Find-AccordLockPostgresCommand -Name 'psql'
    $observed = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $script:AccordLockPostgresPort `
        -U $script:AccordLockPostgresUser -d postgres -tA -c 'SHOW data_directory' 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $text = ($observed -join '').Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return [IO.Path]::GetFullPath($text)
}

function Test-AccordLockOwnedPostgresServer {
    $servingData = Get-AccordLockServingDataDirectory
    if ($null -eq $servingData) {
        return $false
    }
    return $servingData.Equals($script:AccordLockPostgresData, [StringComparison]::OrdinalIgnoreCase)
}
