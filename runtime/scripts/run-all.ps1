[CmdletBinding()]
param(
    [ValidateSet('local', 'external', 'not-requested')]
    [string]$PostgresMode = 'local',
    [string]$TlaJar = $env:TLA2TOOLS_JAR,
    [ValidateSet('exhaustive', 'smoke')]
    [string]$TlaMode = 'exhaustive',
    [switch]$KeepLocalPostgres
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $PSBoundParameters.ContainsKey('TlaMode') -and
    -not [string]::IsNullOrWhiteSpace($env:ACCORDLOCK_TLA_MODE)) {
    if ($env:ACCORDLOCK_TLA_MODE -notin @('exhaustive', 'smoke')) {
        throw "Unknown ACCORDLOCK_TLA_MODE: $($env:ACCORDLOCK_TLA_MODE)"
    }
    $TlaMode = $env:ACCORDLOCK_TLA_MODE
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$localPostgresStartedByRunner = $false
$runIncomplete = $false

function Find-AccordLockCommand {
    param([Parameter(Mandatory)][string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    if ($Name -in @('cargo', 'rustc')) {
        $candidate = Join-Path $env:USERPROFILE ".cargo\bin\$Name.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    if ($Name -eq 'cargo-audit') {
        $candidate = Join-Path $repositoryRoot '.local\tools\cargo-audit\bin\cargo-audit.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw "Required command is missing: $Name"
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

function Invoke-AccordLockStage {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    Write-Output "RUN $Name"
    & $Body
    Write-Output "PASS $Name"
}

Push-Location $repositoryRoot
try {
    $cargo = Find-AccordLockCommand -Name 'cargo'
    $cargoAudit = Find-AccordLockCommand -Name 'cargo-audit'
    $rustc = Find-AccordLockCommand -Name 'rustc'
    $python = Find-AccordLockCommand -Name 'python'
    $java = Find-AccordLockCommand -Name 'java'
    $git = Find-AccordLockCommand -Name 'git'

    Invoke-AccordLockStage -Name 'tool_versions' -Body {
        $toolchainText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'rust-toolchain.toml') -Raw
        $match = [regex]::Match($toolchainText, 'channel\s*=\s*"([^"]+)"')
        if (-not $match.Success) {
            throw 'rust-toolchain.toml does not contain a pinned channel'
        }
        $pinnedRust = $match.Groups[1].Value
        $rustVersion = & $rustc --version
        if ($LASTEXITCODE -ne 0) { throw 'rustc --version failed' }
        if (-not (($rustVersion -join '') -like "rustc $pinnedRust *")) {
            throw "Rust version mismatch: pinned=$pinnedRust observed=$rustVersion"
        }
        Write-Output ($rustVersion -join '')
        Invoke-AccordLockNative -Command $cargo -Arguments @('--version')
        $cargoAuditVersion = & $cargoAudit --version
        if ($LASTEXITCODE -ne 0) { throw 'cargo-audit --version failed' }
        if (($cargoAuditVersion -join '') -ne 'cargo-audit 0.22.2') {
            throw "cargo-audit version mismatch: expected=0.22.2 observed=$cargoAuditVersion"
        }
        Write-Output ($cargoAuditVersion -join '')
        Invoke-AccordLockNative -Command $python -Arguments @('--version')
        Invoke-AccordLockNative -Command $java -Arguments @('-version')
        Invoke-AccordLockNative -Command $git -Arguments @('--version')
    }

    Invoke-AccordLockStage -Name 'rustsec_advisory_audit_no_yanked' -Body {
        $rustSecDb = Join-Path $repositoryRoot '.local\rustsec-advisory-db'
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\check_rustsec_audit.py', '--cargo-audit', $cargoAudit,
            '--git', $git, '--db', $rustSecDb, '--lock',
            (Join-Path $repositoryRoot 'Cargo.lock'), '--expected-commit-file',
            (Join-Path $repositoryRoot 'scripts\rustsec-advisory-db.commit'),
            '--max-age-days', '14'
        )
    }

    Invoke-AccordLockStage -Name 'locked_supply_chain_contract' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\check_supply_chain.py', '--cargo', $cargo
        )
    }

    Invoke-AccordLockStage -Name 'source_manifest_exact' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\source_manifest.py', '--git', $git
        )
    }

    Invoke-AccordLockStage -Name 'repository_contracts_static_only' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @('scripts\validate_repository.py')
    }
    Invoke-AccordLockStage -Name 'synthetic_corpus_oracle_validation' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @('conformance\validate.py')
    }
    Invoke-AccordLockStage -Name 'corpus_validator_negative_tests' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py'
        )
    }
    Invoke-AccordLockStage -Name 'admission_deployment_static_tests' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            '-m', 'unittest', 'discover', '-s', 'infra\kubernetes\admission',
            '-p', 'test_validate.py'
        )
    }
    Invoke-AccordLockStage -Name 'eks_activation_evidence_gate_tests' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            '-m', 'unittest', 'discover', '-s', 'infra\kubernetes\activation',
            '-p', 'test_validate.py'
        )
    }
    Invoke-AccordLockStage -Name 'rustfmt_check' -Body {
        Invoke-AccordLockNative -Command $cargo -Arguments @('fmt', '--all', '--', '--check')
    }
    Invoke-AccordLockStage -Name 'cargo_check_all_targets' -Body {
        Invoke-AccordLockNative -Command $cargo -Arguments @('check', '--workspace', '--locked', '--all-targets')
    }
    Invoke-AccordLockStage -Name 'clippy_deny_warnings' -Body {
        Invoke-AccordLockNative -Command $cargo -Arguments @(
            'clippy', '--workspace', '--locked', '--all-targets', '--', '-D', 'warnings'
        )
    }
    Invoke-AccordLockStage -Name 'rust_tests_non_ignored' -Body {
        Invoke-AccordLockNative -Command $cargo -Arguments @('test', '--workspace', '--locked')
    }
    Invoke-AccordLockStage -Name 'rustc_actual_source_inputs' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\source_manifest.py', '--git', $git, '--dep-info-root',
            (Join-Path $repositoryRoot 'target')
        )
    }
    Invoke-AccordLockStage -Name 'cli_synthetic_demo_determinism' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\check_cli_demo.py', '--cargo', $cargo
        )
    }
    if ($TlaMode -eq 'smoke') {
        Invoke-AccordLockStage -Name 'tla_model_check_smoke' -Body {
            & (Join-Path $PSScriptRoot 'run-tla-smoke.ps1') -Jar $TlaJar
            if ($LASTEXITCODE -ne 0) { throw "TLA smoke runner failed with exit code $LASTEXITCODE" }
        }
    } else {
        Invoke-AccordLockStage -Name 'tla_model_check' -Body {
            & (Join-Path $PSScriptRoot 'run-tla.ps1') -Jar $TlaJar
            if ($LASTEXITCODE -ne 0) { throw "TLA runner failed with exit code $LASTEXITCODE" }
        }
    }

    if ($PostgresMode -eq 'local') {
        $statusScript = Join-Path $repositoryRoot 'infra\local\postgres\status.ps1'
        & $statusScript *> $null
        $postgresWasRunning = $LASTEXITCODE -eq 0
        Invoke-AccordLockStage -Name 'postgres_local_start' -Body {
            & (Join-Path $repositoryRoot 'infra\local\postgres\start.ps1')
            if ($LASTEXITCODE -ne 0) { throw "Local PostgreSQL start failed with exit code $LASTEXITCODE" }
        }
        $localPostgresStartedByRunner = -not $postgresWasRunning
        $env:ACCORDLOCK_TEST_POSTGRES_URL = 'postgresql://postgres@127.0.0.1:55432/accordlock_test_v2'
    } elseif ($PostgresMode -eq 'external') {
        if ([string]::IsNullOrWhiteSpace($env:ACCORDLOCK_TEST_POSTGRES_URL)) {
            throw 'PostgresMode=external requires ACCORDLOCK_TEST_POSTGRES_URL'
        }
        if ($env:ACCORDLOCK_TEST_POSTGRES_V14_RESET -ne 'DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2') {
            throw 'PostgresMode=external requires explicit ACCORDLOCK_TEST_POSTGRES_V14_RESET confirmation'
        }
    } else {
        Write-Output 'NOT_REQUESTED postgres_transactional_test mode=not-requested'
        $runIncomplete = $true
    }

    if ($PostgresMode -ne 'not-requested') {
        $previousStateResetConfirmation = $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET
        try {
            if ($PostgresMode -eq 'local') {
                $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET = 'DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2'
            }
            Invoke-AccordLockStage -Name 'postgres_state_adversarial_invariants' -Body {
                Invoke-AccordLockNative -Command $cargo -Arguments @(
                    'test', '-p', 'accordlock-state', '--test', 'postgres', '--locked', '--',
                    '--ignored', '--test-threads=1'
                )
            }
        } finally {
            if ($PostgresMode -eq 'local') {
                if ($null -eq $previousStateResetConfirmation) {
                    Remove-Item Env:ACCORDLOCK_TEST_POSTGRES_V14_RESET -ErrorAction SilentlyContinue
                } else {
                    $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET = $previousStateResetConfirmation
                }
            }
        }
        $controlV13Arguments = @(
            'test', '-p', 'accordlock-state', '--test', 'postgres_control_v13',
            '--locked', '--', '--ignored', '--test-threads=1'
        )
        if ($TlaMode -eq 'smoke') {
            $controlV13Arguments += @(
                '--skip',
                'postgres_v14_scan_skips_more_than_transient_retry_cap_and_reaches_valid_tail'
            )
            Write-Output 'BOUNDARY postgres_control_v13_smoke omits only the 257-head exhaustive scan; default exhaustive mode retains it'
        }
        Invoke-AccordLockStage -Name 'postgres_control_v13_adversarial_invariants' -Body {
            Invoke-AccordLockNative -Command $cargo -Arguments $controlV13Arguments
        }
        Invoke-AccordLockStage -Name 'postgres_v14_guard_invariants' -Body {
            Invoke-AccordLockNative -Command $cargo -Arguments @(
                'test', '-p', 'accordlock-state', '--test', 'postgres_v14_guards',
                '--locked', '--', '--ignored', '--test-threads=1'
            )
        }
        Invoke-AccordLockStage -Name 'postgres_v14_upgrade_invariants' -Body {
            $previousResetConfirmation = $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET
            try {
                if ($PostgresMode -eq 'local') {
                    $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET = 'DROP_PUBLIC_SCHEMA_OF_ACCORDLOCK_TEST_V2'
                }
                Invoke-AccordLockNative -Command $cargo -Arguments @(
                    'test', '-p', 'accordlock-state', '--test', 'postgres_v14_upgrade',
                    '--locked', '--', '--ignored', '--test-threads=1'
                )
            } finally {
                if ($PostgresMode -eq 'local') {
                    if ($null -eq $previousResetConfirmation) {
                        Remove-Item Env:ACCORDLOCK_TEST_POSTGRES_V14_RESET -ErrorAction SilentlyContinue
                    } else {
                        $env:ACCORDLOCK_TEST_POSTGRES_V14_RESET = $previousResetConfirmation
                    }
                }
            }
        }
        Invoke-AccordLockStage -Name 'postgres_live_session_state_path' -Body {
            Invoke-AccordLockNative -Command $cargo -Arguments @(
                'test', '-p', 'accordlock-cli', '--lib', '--locked',
                'live_k8s::tests::postgres_live_session_persists_receipt_and_outbox', '--',
                '--ignored', '--exact', '--test-threads=1'
            )
        }
        Invoke-AccordLockStage -Name 'postgres_live_session_cli_path' -Body {
            Invoke-AccordLockNative -Command $cargo -Arguments @(
                'test', '-p', 'accordlock-cli', '--test', 'live_postgres_cli', '--locked',
                'cli_postgres_prepare_and_validate_reverify_durable_state', '--',
                '--ignored', '--exact', '--test-threads=1'
            )
        }
    }

    Invoke-AccordLockStage -Name 'source_manifest_exact_final' -Body {
        Invoke-AccordLockNative -Command $python -Arguments @(
            'scripts\source_manifest.py', '--git', $git
        )
    }
} finally {
    if ($localPostgresStartedByRunner -and -not $KeepLocalPostgres) {
        Invoke-AccordLockStage -Name 'postgres_local_stop' -Body {
            & (Join-Path $repositoryRoot 'infra\local\postgres\status.ps1') *> $null
            if ($LASTEXITCODE -ne 0) { throw 'Local PostgreSQL was not running before required cleanup' }
            & (Join-Path $repositoryRoot 'infra\local\postgres\stop.ps1')
            if ($LASTEXITCODE -ne 0) { throw "Local PostgreSQL stop failed with exit code $LASTEXITCODE" }
        }
    } elseif ($localPostgresStartedByRunner) {
        Write-Output 'RUNNING postgres_local_stop reason=KeepLocalPostgres'
    }
    Pop-Location
}

if ($runIncomplete) {
    Write-Output 'INCOMPLETE run_all reason=postgres_not_requested'
    exit 2
}

if ($TlaMode -eq 'smoke') {
    Write-Output 'PASS run_all_smoke scope=static_contracts_rust_tla_smoke_postgres_bounded_live_cli_rustsec tla_mode=smoke'
    Write-Output 'BOUNDARY run_all_smoke is not a full or exhaustive reproducibility result'
    Write-Output 'BOUNDARY run_all_smoke excludes the 257-head PostgreSQL scan retained by exhaustive mode'
} else {
    Write-Output 'PASS run_all scope=static_contracts_rust_tla_postgres_live_cli_rustsec tla_mode=exhaustive'
}
Write-Output 'BOUNDARY conformance scenario manifests were validated but not executed'
Write-Output 'BOUNDARY RustSec advisories were checked; yanked-crate status was not checked'
