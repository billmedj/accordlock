[CmdletBinding()]
param(
    [string]$Jar = $env:TLA2TOOLS_JAR
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$expectedSha256 = '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88'

if ([string]::IsNullOrWhiteSpace($Jar)) {
    $candidate = Join-Path $repositoryRoot '.local\tools\tla2tools.jar'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $Jar = $candidate
    }
}

if ([string]::IsNullOrWhiteSpace($Jar)) {
    Write-Error 'TLC jar is required. Run scripts/fetch_tla2tools.py or set TLA2TOOLS_JAR.'
}

$jarPath = (Resolve-Path -LiteralPath $Jar -ErrorAction Stop).Path
$observedSha256 = (Get-FileHash -LiteralPath $jarPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedSha256 -ne $expectedSha256) {
    Write-Error "TLC jar SHA-256 mismatch: expected=$expectedSha256 observed=$observedSha256"
}

$java = Get-Command java -ErrorAction Stop
$canonicalModels = @(
    'AuthorizationLifecycle',
    'DispatchClaim',
    'PhysicalReservation',
    'AdmissionAuthorization',
    'BrokerJournal',
    'TerminalRetirement',
    'DurableControlQueue'
)
foreach ($model in $canonicalModels) {
    & $java.Source '-XX:+UseParallelGC' -jar $jarPath -workers auto -cleanup -config `
        (Join-Path $repositoryRoot "models\$model.cfg") `
        (Join-Path $repositoryRoot "models\$model.tla")
    if ($LASTEXITCODE -ne 0) {
        Write-Error "TLC smoke check failed for $model with exit code $LASTEXITCODE"
    }
    Write-Output "PASS tla_model_smoke model=$model config=canonical sha256=$observedSha256"
}

& $java.Source '-XX:+UseParallelGC' -jar $jarPath -workers auto -cleanup -config `
    (Join-Path $repositoryRoot 'models\DurableDispatchAcquisitionSmoke.cfg') `
    (Join-Path $repositoryRoot 'models\DurableDispatchAcquisition.tla')
if ($LASTEXITCODE -ne 0) {
    Write-Error "TLC smoke check failed for DurableDispatchAcquisition with exit code $LASTEXITCODE"
}
Write-Output "PASS tla_model_smoke model=DurableDispatchAcquisition config=smoke_max_acquisitions_1_full_search sha256=$observedSha256"

Write-Output "PASS tla_model_check_smoke models=$($canonicalModels.Count + 1) canonical_configs=7 smoke_configs=1 sha256=$observedSha256"
Write-Output 'BOUNDARY tla_model_check_smoke is a complete Max1 search; it is not the canonical exhaustive Max3 result and does not cover Max2 multi-acquisition behavior'
