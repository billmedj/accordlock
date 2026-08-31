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
$models = @(
    'AuthorizationLifecycle',
    'DispatchClaim',
    'PhysicalReservation',
    'AdmissionAuthorization',
    'BrokerJournal',
    'TerminalRetirement',
    'DurableControlQueue',
    'DurableDispatchAcquisition'
)
foreach ($model in $models) {
    & $java.Source '-XX:+UseParallelGC' -jar $jarPath -workers 1 -cleanup -config `
        (Join-Path $repositoryRoot "models\$model.cfg") `
        (Join-Path $repositoryRoot "models\$model.tla")
    if ($LASTEXITCODE -ne 0) {
        Write-Error "TLC failed for $model with exit code $LASTEXITCODE"
    }
    Write-Output "PASS tla_model model=$model sha256=$observedSha256"
}

Write-Output "PASS tla_model_check models=$($models.Count) sha256=$observedSha256"
