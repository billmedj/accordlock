[CmdletBinding()]
param(
    [switch]$RecreateCluster,
    [ValidateSet('in-memory', 'postgres')]
    [string]$StateBackend = 'in-memory',
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')]
    [string]$PostgresUrlEnv = 'ACCORDLOCK_LIVE_POSTGRES_URL',
    [switch]$MigratePostgres,
    [ValidateRange(1, 6)]
    [int]$TimeoutScale = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$KindConfig = Join-Path $PSScriptRoot 'kind-config.yaml'
$NamespaceManifest = Join-Path $PSScriptRoot 'namespace.yaml'
$DeploymentManifest = Join-Path $PSScriptRoot 'deployment.yaml'
$ArtifactDirectory = Join-Path $RepoRoot '.local\live-k8s'
$RunId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss.fffZ'), ([Guid]::NewGuid().ToString('N'))
$RunDirectory = Join-Path (Join-Path $ArtifactDirectory 'runs') $RunId
$CommandDirectory = Join-Path $RunDirectory 'commands'
$RunnerLogPath = Join-Path $RunDirectory 'runner.log'
$CommandEventsPath = Join-Path $RunDirectory 'command-events.jsonl'
$KindLocal = Join-Path $RepoRoot '.local\bin\kind.exe'
$CargoLocal = if ($env:USERPROFILE) {
    Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
}
else {
    $null
}
$AccordLockExe = Join-Path $RepoRoot 'target\debug\accordlock.exe'
$BeforePath = Join-Path $RunDirectory 'before.json'
$SessionPath = Join-Path $RunDirectory 'session.json'
$PatchPath = Join-Path $RunDirectory 'patch.json'
$DryRunResponsePath = Join-Path $RunDirectory 'dry-run-response.json'
$PatchResponsePath = Join-Path $RunDirectory 'patch-response.json'
$AfterPath = Join-Path $RunDirectory 'after.json'
$ReplicaSetsPath = Join-Path $RunDirectory 'replica-sets.json'
$PodsPath = Join-Path $RunDirectory 'pods.json'
$ValidationPath = Join-Path $RunDirectory 'validation.json'
$CandidateValidationPath = Join-Path $RunDirectory 'candidate-validation.json'
$EffectValidationPath = Join-Path $RunDirectory 'effect-validation.json'

$ClusterName = 'accordlock'
$Context = 'kind-accordlock'
$Namespace = 'accordlock-demo'
$Deployment = 'payments'
$KindVersion = 'v0.32.0'
$NodeImage = 'kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
$NewImage = 'docker.io/library/nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236'
$PriorImage = 'docker.io/library/nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'
$ProfileLabel = 'deploy-eks-image-v1'

$script:CommandIndex = 0
$script:StageIndex = 0
$script:CurrentStage = 'initialization'
$script:SensitiveValues = @()
$script:ClusterMutationStarted = $false

$RunsDirectory = Split-Path -Parent $RunDirectory
New-Item -ItemType Directory -Force -Path $RunsDirectory | Out-Null
New-Item -ItemType Directory -Path $RunDirectory | Out-Null
New-Item -ItemType Directory -Path $CommandDirectory | Out-Null

function Write-RunEvent {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $SafeMessage = Protect-SensitiveText -Text $Message
    $Line = "[$Timestamp][$Level] $SafeMessage"
    Write-Host $Line
    Add-Content -LiteralPath $RunnerLogPath -Value $Line -Encoding utf8
}

function Start-RunnerStage {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $script:StageIndex++
    $script:CurrentStage = $Name
    Write-RunEvent -Message ("STAGE {0:D2}: {1}" -f $script:StageIndex, $Name)
}

function Resolve-NativeCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [string]$PreferredPath
    )

    if ($PreferredPath -and (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $PreferredPath).Path
    }
    $Resolved = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $Resolved) {
        throw "Required executable '$Name' was not found."
    }
    return $Resolved.Source
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return ($Value -replace '[^A-Za-z0-9_.-]', '_')
}

function Protect-SensitiveText {
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    $Protected = $Text
    foreach ($SensitiveValue in $script:SensitiveValues) {
        if (-not [string]::IsNullOrEmpty($SensitiveValue)) {
            $Protected = $Protected.Replace($SensitiveValue, '[REDACTED]')
        }
    }
    return $Protected
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$Executable,
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [ValidateRange(1, 1800)]
        [int]$TimeoutSeconds = 60
    )

    $EffectiveTimeoutSeconds = [Math]::Min(1800, $TimeoutSeconds * $TimeoutScale)
    $script:CommandIndex++
    $CommandStem = '{0:D2}-{1}' -f $script:CommandIndex, (ConvertTo-SafeFileName -Value $Label)
    $StdoutPath = Join-Path $CommandDirectory "$CommandStem.stdout.log"
    $StderrPath = Join-Path $CommandDirectory "$CommandStem.stderr.log"
    $StartedAt = (Get-Date).ToUniversalTime()
    $LoggedArguments = @($Arguments | ForEach-Object {
        Protect-SensitiveText -Text $_
    })
    Write-RunEvent -Message "COMMAND $CommandStem (timeout ${EffectiveTimeoutSeconds}s): $Executable"

    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $StartInfo.FileName = $Executable
    $StartInfo.WorkingDirectory = $RepoRoot
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in $Arguments) {
        [void]$StartInfo.ArgumentList.Add($Argument)
    }

    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $StartInfo
    $TimedOut = $false
    try {
        try {
            $Started = $Process.Start()
        }
        catch {
            $StartError = Protect-SensitiveText -Text $_.Exception.Message
            Set-Content -LiteralPath $StdoutPath -Value '' -Encoding utf8NoBOM
            Set-Content -LiteralPath $StderrPath -Value $StartError -Encoding utf8NoBOM
            [ordered]@{
                label = $Label
                executable = $Executable
                arguments = $LoggedArguments
                started_at = $StartedAt.ToString('o')
                finished_at = (Get-Date).ToUniversalTime().ToString('o')
                timeout_seconds = $EffectiveTimeoutSeconds
                base_timeout_seconds = $TimeoutSeconds
                timeout_scale = $TimeoutScale
                start_failed = $true
                timed_out = $false
                output_drain_completed = $true
                exit_code = $null
                stdout = $StdoutPath
                stderr = $StderrPath
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $CommandEventsPath -Encoding utf8
            throw "Native command '$Label' could not start. Diagnostics: '$StdoutPath', '$StderrPath'."
        }
        if (-not $Started) {
            throw "Native command '$Label' returned no process."
        }
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit($EffectiveTimeoutSeconds * 1000)) {
            $TimedOut = $true
            try {
                $Process.Kill($true)
            }
            catch {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
            [void]$Process.WaitForExit(10000)
        }
        else {
            $Process.WaitForExit()
        }

        $OutputTasks = [System.Threading.Tasks.Task[]]@($StdoutTask, $StderrTask)
        $OutputDrainCompleted = [System.Threading.Tasks.Task]::WaitAll($OutputTasks, 10000)
        if ($OutputDrainCompleted) {
            $Stdout = Protect-SensitiveText -Text $StdoutTask.GetAwaiter().GetResult()
            $Stderr = Protect-SensitiveText -Text $StderrTask.GetAwaiter().GetResult()
        }
        else {
            $Stdout = ''
            $Stderr = 'Process output pipes did not close within 10 seconds after termination.'
        }
        Set-Content -LiteralPath $StdoutPath -Value $Stdout -Encoding utf8NoBOM
        Set-Content -LiteralPath $StderrPath -Value $Stderr -Encoding utf8NoBOM
        $FinishedAt = (Get-Date).ToUniversalTime()
        $ExitCode = if ($TimedOut) { $null } else { $Process.ExitCode }
        [ordered]@{
            label = $Label
            executable = $Executable
            arguments = $LoggedArguments
            started_at = $StartedAt.ToString('o')
            finished_at = $FinishedAt.ToString('o')
            timeout_seconds = $EffectiveTimeoutSeconds
            base_timeout_seconds = $TimeoutSeconds
            timeout_scale = $TimeoutScale
            start_failed = $false
            timed_out = $TimedOut
            output_drain_completed = $OutputDrainCompleted
            exit_code = $ExitCode
            stdout = $StdoutPath
            stderr = $StderrPath
        } | ConvertTo-Json -Compress | Add-Content -LiteralPath $CommandEventsPath -Encoding utf8

        if ($TimedOut) {
            throw "Native command '$Label' exceeded ${EffectiveTimeoutSeconds}s and was terminated. Diagnostics: '$StdoutPath', '$StderrPath'."
        }
        if (-not $OutputDrainCompleted) {
            throw "Native command '$Label' exited but its output pipes did not close within 10 seconds. Diagnostics: '$StdoutPath', '$StderrPath'."
        }
        if ($ExitCode -ne 0) {
            $StderrSummary = ($Stderr.Trim() -replace "`r?`n", ' ')
            if ($StderrSummary.Length -gt 300) {
                $StderrSummary = $StderrSummary.Substring(0, 300) + '...'
            }
            throw "Native command '$Label' failed with exit code $ExitCode. $StderrSummary Diagnostics: '$StdoutPath', '$StderrPath'."
        }
        return $Stdout.TrimEnd("`r", "`n")
    }
    finally {
        $Process.Dispose()
    }
}

function ConvertTo-NameList {
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }
    return @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-LiveStateRecordRef {
    param(
        [AllowNull()]
        [object]$Reference
    )

    return $null -ne $Reference `
        -and -not [string]::IsNullOrWhiteSpace([string]$Reference.tenant) `
        -and -not [string]::IsNullOrWhiteSpace([string]$Reference.environment) `
        -and -not [string]::IsNullOrWhiteSpace([string]$Reference.transaction_id) `
        -and -not [string]::IsNullOrWhiteSpace([string]$Reference.authorization_id)
}

function Get-OptionalCollectionCount {
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $Property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return 0
    }
    return @($Property.Value).Count
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $Property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $Property) {
        return $null
    }
    return $Property.Value
}

function Test-AbsentNullOrFalse {
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $Value = Get-OptionalPropertyValue -Object $Object -PropertyName $PropertyName
    return $null -eq $Value -or $Value -eq $false
}

function Get-ClusterInventory {
    $ClusterText = Invoke-NativeCommand -Label 'kind-get-clusters' -Executable $Kind -Arguments @(
        'get', 'clusters'
    ) -TimeoutSeconds 30
    $ContextText = Invoke-NativeCommand -Label 'kubectl-get-contexts' -Executable $Kubectl -Arguments @(
        'config', 'get-contexts', '-o', 'name'
    ) -TimeoutSeconds 20
    $Clusters = @(ConvertTo-NameList -Text $ClusterText)
    $Contexts = @(ConvertTo-NameList -Text $ContextText)
    return [pscustomobject]@{
        ClusterExists = $Clusters -contains $ClusterName
        ContextExists = $Contexts -contains $Context
        Clusters = $Clusters
        Contexts = $Contexts
    }
}

function Assert-ClusterIdentityAndHealth {
    $NodeText = Invoke-NativeCommand -Label 'kind-get-nodes' -Executable $Kind -Arguments @(
        'get', 'nodes', '--name', $ClusterName
    ) -TimeoutSeconds 30
    $Nodes = @(ConvertTo-NameList -Text $NodeText)
    if ($Nodes.Count -ne 1) {
        throw "The local profile requires exactly one kind node; observed $($Nodes.Count). Refusing to continue. Use -RecreateCluster explicitly if replacement is intended."
    }

    $NodeInspection = Invoke-NativeCommand -Label 'docker-inspect-kind-node' -Executable $Docker -Arguments @(
        'inspect',
        '--format', '{{.Config.Image}}|{{index .Config.Labels "io.x-k8s.kind.cluster"}}|{{index .Config.Labels "io.x-k8s.kind.role"}}|{{.State.Status}}',
        $Nodes[0]
    ) -TimeoutSeconds 20
    $NodeFields = @($NodeInspection.Trim() -split '\|', 4)
    if ($NodeFields.Count -ne 4) {
        throw "Could not establish the identity of kind node '$($Nodes[0])'. Refusing to continue."
    }
    if ($NodeFields[0] -ne $NodeImage) {
        throw "Existing kind node image is not the pinned profile image. Expected '$NodeImage', observed '$($NodeFields[0])'. Use -RecreateCluster explicitly."
    }
    if ($NodeFields[1] -ne $ClusterName -or $NodeFields[2] -ne 'control-plane') {
        throw "Container '$($Nodes[0])' does not have the expected kind cluster and role labels. Refusing to continue."
    }
    if ($NodeFields[3] -ne 'running') {
        throw "Kind node '$($Nodes[0])' is '$($NodeFields[3])', not running. Refusing to continue; no automatic restart is attempted."
    }

    $ContextJson = Invoke-NativeCommand -Label 'kubectl-inspect-context' -Executable $Kubectl -Arguments @(
        'config', 'view', '--context', $Context, '--minify', '-o', 'json'
    ) -TimeoutSeconds 20
    $ContextObject = $ContextJson | ConvertFrom-Json -Depth 100
    $ExpectedKubeCluster = "kind-$ClusterName"
    if (@($ContextObject.contexts).Count -ne 1 `
        -or @($ContextObject.clusters).Count -ne 1 `
        -or $ContextObject.contexts[0].name -ne $Context `
        -or $ContextObject.contexts[0].context.cluster -ne $ExpectedKubeCluster `
        -or $ContextObject.clusters[0].name -ne $ExpectedKubeCluster) {
        throw "Kubeconfig context '$Context' is incomplete or points at a different cluster. Refusing to continue."
    }

    $KubeNodesJson = Invoke-NativeCommand -Label 'kubectl-get-nodes' -Executable $Kubectl -Arguments @(
        '--context', $Context, 'get', 'nodes', '-o', 'json'
    ) -TimeoutSeconds 30
    $KubeNodes = $KubeNodesJson | ConvertFrom-Json -Depth 100
    if (@($KubeNodes.items).Count -ne 1 -or $KubeNodes.items[0].metadata.name -ne $Nodes[0]) {
        throw "Kubernetes API node inventory does not match the kind container inventory. Refusing to continue."
    }
    $ReadyCondition = @($KubeNodes.items[0].status.conditions | Where-Object { $_.type -eq 'Ready' })
    if ($ReadyCondition.Count -ne 1 -or $ReadyCondition[0].status -ne 'True') {
        throw "Kubernetes node '$($Nodes[0])' is not Ready. Refusing to mutate the cluster."
    }
}

function Assert-ProfileResourceOwnership {
    $NamespaceJson = Invoke-NativeCommand -Label 'kubectl-inspect-profile-namespace' -Executable $Kubectl -Arguments @(
        '--context', $Context, 'get', 'namespace', $Namespace, '--ignore-not-found', '-o', 'json'
    ) -TimeoutSeconds 30
    if ([string]::IsNullOrWhiteSpace($NamespaceJson)) {
        return
    }
    $ExistingNamespace = $NamespaceJson | ConvertFrom-Json -Depth 100
    if ($ExistingNamespace.metadata.labels.'accordlock.io/profile' -ne $ProfileLabel `
        -or $null -ne (Get-OptionalPropertyValue -Object $ExistingNamespace.metadata -PropertyName 'deletionTimestamp') `
        -or $ExistingNamespace.status.phase -ne 'Active') {
        throw "Namespace '$Namespace' exists without the expected active AccordLock profile ownership state. Refusing to modify it."
    }

    $ServiceAccountJson = Invoke-NativeCommand -Label 'kubectl-inspect-profile-service-account' -Executable $Kubectl -Arguments @(
        '--context', $Context, '-n', $Namespace, 'get', 'serviceaccount', 'payments-runtime',
        '--ignore-not-found', '-o', 'json'
    ) -TimeoutSeconds 30
    if (-not [string]::IsNullOrWhiteSpace($ServiceAccountJson)) {
        $ExistingServiceAccount = $ServiceAccountJson | ConvertFrom-Json -Depth 100
        if ($ExistingServiceAccount.metadata.labels.'accordlock.io/profile' -ne $ProfileLabel `
            -or $null -ne (Get-OptionalPropertyValue -Object $ExistingServiceAccount.metadata -PropertyName 'deletionTimestamp') `
            -or $ExistingServiceAccount.automountServiceAccountToken -ne $false `
            -or (Get-OptionalCollectionCount -Object $ExistingServiceAccount -PropertyName 'secrets') -ne 0 `
            -or (Get-OptionalCollectionCount -Object $ExistingServiceAccount -PropertyName 'imagePullSecrets') -ne 0) {
            throw "ServiceAccount '$Namespace/payments-runtime' exists but is not owned by the AccordLock demo profile. Refusing to apply over it."
        }
    }

    $DeploymentJson = Invoke-NativeCommand -Label 'kubectl-inspect-profile-deployment' -Executable $Kubectl -Arguments @(
        '--context', $Context, '-n', $Namespace, 'get', 'deployment', $Deployment,
        '--ignore-not-found', '-o', 'json'
    ) -TimeoutSeconds 30
    if ([string]::IsNullOrWhiteSpace($DeploymentJson)) {
        return
    }

    $ExistingDeployment = $DeploymentJson | ConvertFrom-Json -Depth 100
    $Containers = @($ExistingDeployment.spec.template.spec.containers)
    $Annotations = $ExistingDeployment.metadata.annotations
    $AnnotationNames = if ($null -eq $Annotations) {
        @()
    }
    else {
        @($Annotations.PSObject.Properties.Name)
    }
    $RequiredAnnotations = @(
        'accordlock.io/transaction-id',
        'accordlock.io/authorization-id',
        'accordlock.io/operation-hash'
    )
    $MissingAnnotations = @($RequiredAnnotations | Where-Object { $AnnotationNames -notcontains $_ })
    $InitContainerCount = Get-OptionalCollectionCount -Object $ExistingDeployment.spec.template.spec -PropertyName 'initContainers'
    $EphemeralContainerCount = Get-OptionalCollectionCount -Object $ExistingDeployment.spec.template.spec -PropertyName 'ephemeralContainers'
    $VolumeCount = Get-OptionalCollectionCount -Object $ExistingDeployment.spec.template.spec -PropertyName 'volumes'
    $ImagePullSecretCount = Get-OptionalCollectionCount -Object $ExistingDeployment.spec.template.spec -PropertyName 'imagePullSecrets'
    $NodeSelectorCount = if ($null -eq (Get-OptionalPropertyValue -Object $ExistingDeployment.spec.template.spec -PropertyName 'nodeSelector')) {
        0
    }
    else {
        @((Get-OptionalPropertyValue -Object $ExistingDeployment.spec.template.spec -PropertyName 'nodeSelector').PSObject.Properties).Count
    }
    $ContainerEnvironmentCount = Get-OptionalCollectionCount -Object $Containers[0] -PropertyName 'env'
    $ContainerEnvironmentFromCount = Get-OptionalCollectionCount -Object $Containers[0] -PropertyName 'envFrom'
    $ContainerVolumeMountCount = Get-OptionalCollectionCount -Object $Containers[0] -PropertyName 'volumeMounts'
    $ContainerSecurityContext = Get-OptionalPropertyValue -Object $Containers[0] -PropertyName 'securityContext'
    $AllowedExistingImages = @($PriorImage, $NewImage)
    if ($ExistingDeployment.metadata.labels.'accordlock.io/profile' -ne $ProfileLabel `
        -or $null -ne (Get-OptionalPropertyValue -Object $ExistingDeployment.metadata -PropertyName 'deletionTimestamp') `
        -or $ExistingDeployment.spec.replicas -ne 1 `
        -or $ExistingDeployment.spec.selector.matchLabels.app -ne 'payments' `
        -or $ExistingDeployment.spec.template.spec.serviceAccountName -ne 'payments-runtime' `
        -or $ExistingDeployment.spec.template.spec.automountServiceAccountToken -ne $false `
        -or -not (Test-AbsentNullOrFalse -Object $ExistingDeployment.spec -PropertyName 'paused') `
        -or -not (Test-AbsentNullOrFalse -Object $ExistingDeployment.spec.template.spec -PropertyName 'hostNetwork') `
        -or -not (Test-AbsentNullOrFalse -Object $ExistingDeployment.spec.template.spec -PropertyName 'hostPID') `
        -or -not (Test-AbsentNullOrFalse -Object $ExistingDeployment.spec.template.spec -PropertyName 'hostIPC') `
        -or -not (Test-AbsentNullOrFalse -Object $ExistingDeployment.spec.template.spec -PropertyName 'shareProcessNamespace') `
        -or $Containers.Count -ne 1 `
        -or $Containers[0].name -ne 'app' `
        -or $AllowedExistingImages -notcontains $Containers[0].image `
        -or $InitContainerCount -ne 0 `
        -or $EphemeralContainerCount -ne 0 `
        -or $VolumeCount -ne 0 `
        -or $ImagePullSecretCount -ne 0 `
        -or $NodeSelectorCount -ne 0 `
        -or $null -ne (Get-OptionalPropertyValue -Object $ExistingDeployment.spec.template.spec -PropertyName 'runtimeClassName') `
        -or $null -ne (Get-OptionalPropertyValue -Object $ExistingDeployment.spec.template.spec -PropertyName 'affinity') `
        -or (Get-OptionalCollectionCount -Object $ExistingDeployment.spec.template.spec -PropertyName 'tolerations') -ne 0 `
        -or $ContainerEnvironmentCount -ne 0 `
        -or $ContainerEnvironmentFromCount -ne 0 `
        -or $ContainerVolumeMountCount -ne 0 `
        -or $null -ne $ContainerSecurityContext `
        -or $null -ne (Get-OptionalPropertyValue -Object $Containers[0] -PropertyName 'command') `
        -or $null -ne (Get-OptionalPropertyValue -Object $Containers[0] -PropertyName 'args') `
        -or $MissingAnnotations.Count -ne 0) {
        throw "Deployment '$Namespace/$Deployment' exists but does not match the owned AccordLock demo profile. Refusing to apply over it."
    }
}

function Write-RunResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('success', 'failure')]
        [string]$Status,
        [string]$ErrorMessage
    )

    $ResultPath = Join-Path $RunDirectory "$Status.json"
    $Result = [ordered]@{
        schema_version = 1
        run_id = $RunId
        status = $Status
        stage = $script:CurrentStage
        finished_at = (Get-Date).ToUniversalTime().ToString('o')
        recreate_cluster_requested = [bool]$RecreateCluster
        state_backend = $StateBackend
        postgres_url_environment_name = if ($StateBackend -eq 'postgres') { $PostgresUrlEnv } else { $null }
        migrate_postgres_requested = [bool]$MigratePostgres
        timeout_scale = $TimeoutScale
        cluster_mutation_started = $script:ClusterMutationStarted
        run_directory = $RunDirectory
        validation_path = if (Test-Path -LiteralPath $ValidationPath -PathType Leaf) { $ValidationPath } else { $null }
        candidate_validation_path = if (Test-Path -LiteralPath $CandidateValidationPath -PathType Leaf) { $CandidateValidationPath } else { $null }
        effect_validation_path = if (Test-Path -LiteralPath $EffectValidationPath -PathType Leaf) { $EffectValidationPath } else { $null }
        error = $ErrorMessage
    }
    $Result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ResultPath -Encoding utf8NoBOM
}

[ordered]@{
    schema_version = 1
    run_id = $RunId
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    repository = $RepoRoot
    recreate_cluster_requested = [bool]$RecreateCluster
    state_backend = $StateBackend
    postgres_url_environment_name = if ($StateBackend -eq 'postgres') { $PostgresUrlEnv } else { $null }
    migrate_postgres_requested = [bool]$MigratePostgres
    timeout_scale = $TimeoutScale
    cluster = $ClusterName
    context = $Context
    required_kind_version = $KindVersion
    node_image = $NodeImage
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $RunDirectory 'run-metadata.json') -Encoding utf8NoBOM

try {
    Start-RunnerStage -Name 'Validate runner options and resolve executables'
    if ($MigratePostgres -and $StateBackend -ne 'postgres') {
        throw '-MigratePostgres is valid only with -StateBackend postgres.'
    }
    if ($StateBackend -eq 'postgres') {
        $PostgresUrl = [Environment]::GetEnvironmentVariable($PostgresUrlEnv)
        if ([string]::IsNullOrWhiteSpace($PostgresUrl)) {
            throw "PostgreSQL mode requires a nonempty process environment variable named '$PostgresUrlEnv'."
        }
        $script:SensitiveValues += $PostgresUrl
        $PostgresUrl = $null
        Write-RunEvent -Message "PostgreSQL mode selected; connection material will be read by AccordLock from environment variable '$PostgresUrlEnv' and will not be logged."
    }
    $Docker = Resolve-NativeCommand -Name 'docker'
    $Kubectl = Resolve-NativeCommand -Name 'kubectl'
    $Cargo = Resolve-NativeCommand -Name 'cargo' -PreferredPath $CargoLocal
    $Kind = Resolve-NativeCommand -Name 'kind' -PreferredPath $KindLocal
    Write-RunEvent -Message "Run diagnostics: $RunDirectory"

    $KindVersionOutput = Invoke-NativeCommand -Label 'kind-version' -Executable $Kind -Arguments @(
        'version'
    ) -TimeoutSeconds 20
    $KindVersionOutput = $KindVersionOutput.Trim()
    if ($KindVersionOutput -notmatch ('^kind\s+' + [regex]::Escape($KindVersion) + '(?:\s|$)')) {
        throw "The local profile requires kind $KindVersion; observed '$KindVersionOutput'. Run '.\infra\local\k8s\install-kind.ps1' to install the reviewed binary."
    }
    Write-RunEvent -Message "kind version: $KindVersionOutput"

    Start-RunnerStage -Name 'Verify bounded Docker access'
    $DockerVersion = Invoke-NativeCommand -Label 'docker-info' -Executable $Docker -Arguments @(
        'info', '--format', '{{.ServerVersion}}'
    ) -TimeoutSeconds 20
    Write-RunEvent -Message "Docker server version: $($DockerVersion.Trim())"
    $DockerCgroupVersion = Invoke-NativeCommand -Label 'docker-cgroup-version' -Executable $Docker -Arguments @(
        'info', '--format', '{{.CgroupVersion}}'
    ) -TimeoutSeconds 20
    $DockerCgroupVersion = $DockerCgroupVersion.Trim()
    if ($DockerCgroupVersion -ne '2') {
        throw "The pinned Kubernetes 1.35 kind profile requires Docker cgroup v2; Docker reported '$DockerCgroupVersion'. Configure the Linux container host for cgroup v2, then retry. Refusing before cluster mutation."
    }
    Write-RunEvent -Message 'Docker cgroup version: 2'

    Start-RunnerStage -Name 'Inspect kind cluster and kubeconfig state'
    $Inventory = Get-ClusterInventory
    if ($Inventory.ClusterExists -ne $Inventory.ContextExists -and -not $RecreateCluster) {
        throw "Cluster '$ClusterName' and context '$Context' are not both present. This is an incomplete local state. Refusing automatic repair; use -RecreateCluster explicitly if replacement is intended."
    }

    if ($RecreateCluster -and ($Inventory.ClusterExists -or $Inventory.ContextExists)) {
        Start-RunnerStage -Name 'Explicitly delete the named AccordLock cluster'
        $script:ClusterMutationStarted = $true
        [void](Invoke-NativeCommand -Label 'kind-delete-cluster' -Executable $Kind -Arguments @(
            'delete', 'cluster', '--name', $ClusterName
        ) -TimeoutSeconds 120)
        $Inventory = Get-ClusterInventory
        if ($Inventory.ClusterExists -or $Inventory.ContextExists) {
            throw "The explicitly requested deletion did not remove both cluster '$ClusterName' and context '$Context'. Refusing to create over partial state."
        }
    }

    if (-not $Inventory.ClusterExists) {
        Start-RunnerStage -Name 'Create the pinned local kind cluster'
        $script:ClusterMutationStarted = $true
        [void](Invoke-NativeCommand -Label 'kind-create-cluster' -Executable $Kind -Arguments @(
            'create', 'cluster',
            '--name', $ClusterName,
            '--config', $KindConfig,
            '--image', $NodeImage,
            '--wait', '120s'
        ) -TimeoutSeconds 180)
        $Inventory = Get-ClusterInventory
        if (-not $Inventory.ClusterExists -or -not $Inventory.ContextExists) {
            throw "kind returned success but cluster '$ClusterName' and context '$Context' are not both present. Refusing to continue."
        }
    }
    else {
        Write-RunEvent -Message "Reusing existing cluster '$ClusterName'; no deletion or recreation was requested."
    }

    Start-RunnerStage -Name 'Verify cluster identity and health'
    Assert-ClusterIdentityAndHealth

    Start-RunnerStage -Name 'Verify demo resource ownership before mutation'
    Assert-ProfileResourceOwnership

    Start-RunnerStage -Name 'Apply pinned demo manifests'
    $script:ClusterMutationStarted = $true
    [void](Invoke-NativeCommand -Label 'kubectl-apply-namespace' -Executable $Kubectl -Arguments @(
        '--context', $Context, 'apply', '-f', $NamespaceManifest
    ) -TimeoutSeconds 60)
    [void](Invoke-NativeCommand -Label 'kubectl-apply-deployment' -Executable $Kubectl -Arguments @(
        '--context', $Context, 'apply', '-f', $DeploymentManifest
    ) -TimeoutSeconds 60)
    [void](Invoke-NativeCommand -Label 'kubectl-rollout-baseline' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'rollout', 'status', "deployment/$Deployment",
        '--timeout=120s'
    ) -TimeoutSeconds 150)

    Start-RunnerStage -Name 'Re-verify the applied baseline profile'
    Assert-ProfileResourceOwnership

    Start-RunnerStage -Name 'Capture the live pre-action Deployment'
    $BeforeJson = Invoke-NativeCommand -Label 'kubectl-get-before' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'get', 'deployment', $Deployment,
        '-o', 'json'
    ) -TimeoutSeconds 30
    Set-Content -LiteralPath $BeforePath -Value $BeforeJson -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Build the locked AccordLock CLI'
    [void](Invoke-NativeCommand -Label 'cargo-build-accordlock-cli' -Executable $Cargo -Arguments @(
        'build', '--locked', '-p', 'accordlock-cli'
    ) -TimeoutSeconds 600)
    if (-not (Test-Path -LiteralPath $AccordLockExe -PathType Leaf)) {
        throw "Cargo returned success but '$AccordLockExe' was not produced."
    }

    Start-RunnerStage -Name 'Prepare and consume a signed local session'
    $PrepareArguments = @(
        'live', 'prepare',
        '--deployment', $BeforePath,
        '--new-image', $NewImage,
        '--session-out', $SessionPath,
        '--patch-out', $PatchPath,
        '--state-backend', $StateBackend
    )
    if ($StateBackend -eq 'postgres') {
        $PrepareArguments += @('--postgres-url-env', $PostgresUrlEnv)
        if ($MigratePostgres) {
            $PrepareArguments += '--migrate-postgres'
        }
    }
    [void](Invoke-NativeCommand -Label 'accordlock-live-prepare' -Executable $AccordLockExe -Arguments $PrepareArguments -TimeoutSeconds 60)
    if (-not (Test-Path -LiteralPath $SessionPath -PathType Leaf)) {
        throw "AccordLock prepare returned success but did not create '$SessionPath'."
    }
    if (-not (Test-Path -LiteralPath $PatchPath -PathType Leaf)) {
        throw "AccordLock prepare returned success but did not create the exact committed patch body '$PatchPath'."
    }
    # Read the generated provider body exactly once. Both the dry-run and the
    # real request use this immutable in-process value; the diagnostic file is
    # never reopened as an execution input after candidate validation.
    $PatchJson = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $PatchPath))
    if ([string]::IsNullOrWhiteSpace($PatchJson)) {
        throw 'AccordLock produced an empty JSON Patch body.'
    }
    $Session = Get-Content -LiteralPath $SessionPath -Raw | ConvertFrom-Json -Depth 100
    $ExpectedSessionBackend = if ($StateBackend -eq 'postgres') { 'POSTGRESQL' } else { 'IN_MEMORY' }
    $ExpectedDurability = $StateBackend -eq 'postgres'
    $ParsedStateInstanceId = [Guid]::Empty
    $StateInstanceIdValid = if ($StateBackend -eq 'postgres') {
        [Guid]::TryParse([string]$Session.state_instance_id, [ref]$ParsedStateInstanceId) `
            -and $ParsedStateInstanceId -ne [Guid]::Empty
    }
    else {
        $null -eq $Session.state_instance_id
    }
    if ($Session.schema_version -ne 4 `
        -or $Session.state_backend -ne $ExpectedSessionBackend `
        -or $Session.durable_consumption -ne $ExpectedDurability `
        -or -not $StateInstanceIdValid) {
        throw "Session schema, state backend, durability, or state-lineage identity does not match requested mode '$StateBackend'."
    }
    if ($StateBackend -eq 'postgres' `
        -and (-not (Test-LiveStateRecordRef -Reference $Session.consumption_receipt_ref) `
            -or -not (Test-LiveStateRecordRef -Reference $Session.execution_outbox_ref) `
            -or $Session.execution_outbox_status -ne 'PENDING_WITNESS')) {
        throw 'PostgreSQL session is missing its durable receipt or pending execution-outbox reference.'
    }

    Start-RunnerStage -Name 'Preflight the exact patch through server-side dry-run admission'
    $DryRunResponse = Invoke-NativeCommand -Label 'kubectl-patch-dry-run' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'patch', 'deployment', $Deployment,
        '--type=json',
        '--patch', $PatchJson,
        '--dry-run=server',
        '-o', 'json'
    ) -TimeoutSeconds 60
    Set-Content -LiteralPath $DryRunResponsePath -Value $DryRunResponse -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Validate the server-side dry-run admission candidate'
    $CandidateValidationJson = Invoke-NativeCommand -Label 'accordlock-live-validate-candidate' -Executable $AccordLockExe -Arguments @(
        'live', 'validate-candidate',
        '--session', $SessionPath,
        '--candidate', $DryRunResponsePath
    ) -TimeoutSeconds 60
    $CandidateValidation = $CandidateValidationJson | ConvertFrom-Json -Depth 100
    if ($CandidateValidation.schema_version -ne 1 `
        -or $CandidateValidation.validation_kind -ne 'LOCAL_LIVE_KUBERNETES_SERVER_DRY_RUN_CANDIDATE' `
        -or $CandidateValidation.benchmark -ne $false `
        -or $CandidateValidation.authorized_delta -ne $true `
        -or $CandidateValidation.evaluation_signature_valid -ne $true `
        -or $CandidateValidation.authorization_signature_valid -ne $true `
        -or $CandidateValidation.session_bindings_valid -ne $true `
        -or $CandidateValidation.full_projection_valid -ne $true `
        -or $CandidateValidation.state_backend -ne $ExpectedSessionBackend `
        -or $CandidateValidation.durable_consumption -ne $ExpectedDurability `
        -or $CandidateValidation.state_records_reverified -ne $false) {
        throw 'AccordLock rejected or incompletely validated the server-side dry-run candidate.'
    }
    Set-Content -LiteralPath $CandidateValidationPath -Value $CandidateValidationJson -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Apply the exact authorization-bound JSON Patch'
    $PatchResponse = Invoke-NativeCommand -Label 'kubectl-patch-deployment' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'patch', 'deployment', $Deployment,
        '--type=json',
        '--patch', $PatchJson,
        '-o', 'json'
    ) -TimeoutSeconds 60
    Set-Content -LiteralPath $PatchResponsePath -Value $PatchResponse -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Validate the persisted API-server response'
    $ValidateArguments = @(
        'live', 'validate',
        '--session', $SessionPath,
        '--after', $PatchResponsePath,
        '--state-backend', $StateBackend
    )
    if ($StateBackend -eq 'postgres') {
        $ValidateArguments += @('--postgres-url-env', $PostgresUrlEnv)
    }
    $ValidationJson = Invoke-NativeCommand -Label 'accordlock-live-validate' -Executable $AccordLockExe -Arguments $ValidateArguments -TimeoutSeconds 60
    $Validation = $ValidationJson | ConvertFrom-Json -Depth 100
    if ($Validation.schema_version -ne 1 `
        -or $Validation.validation_kind -ne 'LOCAL_LIVE_KUBERNETES_PERSISTED_RESPONSE' `
        -or $Validation.benchmark -ne $false `
        -or $Validation.authorized_delta -ne $true `
        -or $Validation.evaluation_signature_valid -ne $true `
        -or $Validation.authorization_signature_valid -ne $true `
        -or $Validation.session_bindings_valid -ne $true `
        -or $Validation.full_projection_valid -ne $true `
        -or $Validation.state_backend -ne $ExpectedSessionBackend `
        -or $Validation.durable_consumption -ne $ExpectedDurability `
        -or $Validation.state_records_reverified -ne $ExpectedDurability) {
        throw 'AccordLock emitted a validation report that does not assert every required persisted-response check.'
    }
    Set-Content -LiteralPath $ValidationPath -Value $ValidationJson -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Verify the eventual controller-managed effect'
    [void](Invoke-NativeCommand -Label 'kubectl-rollout-authorized-effect' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'rollout', 'status', "deployment/$Deployment",
        '--timeout=120s'
    ) -TimeoutSeconds 150)
    $AfterJson = Invoke-NativeCommand -Label 'kubectl-get-after' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'get', 'deployment', $Deployment,
        '-o', 'json'
    ) -TimeoutSeconds 30
    Set-Content -LiteralPath $AfterPath -Value $AfterJson -Encoding utf8NoBOM
    $After = $AfterJson | ConvertFrom-Json -Depth 100
    $ExpectedImage = "$($Session.proposal.template.image_repository)@$($Session.proposal.template.image_digest)"
    $ObservedContainer = @($After.spec.template.spec.containers | Where-Object { $_.name -eq 'app' })
    if ($ObservedContainer.Count -ne 1 -or $ObservedContainer[0].image -ne $ExpectedImage) {
        throw "Final Deployment image does not equal the authorization-bound image '$ExpectedImage'."
    }
    $FinalAnnotations = $After.metadata.annotations
    if ($FinalAnnotations.'accordlock.io/transaction-id' -ne $Session.transaction_id `
        -or $FinalAnnotations.'accordlock.io/authorization-id' -ne $Session.signed_authorization.authorization.authorization_id `
        -or $FinalAnnotations.'accordlock.io/operation-hash' -ne $Session.prepared_patch.operation_hash) {
        throw 'Final Deployment lost one or more authorization-bound AccordLock annotations.'
    }

    $ReplicaSetsJson = Invoke-NativeCommand -Label 'kubectl-get-rollout-replica-sets' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'get', 'replicasets',
        '-l', 'app=payments',
        '-o', 'json'
    ) -TimeoutSeconds 30
    Set-Content -LiteralPath $ReplicaSetsPath -Value $ReplicaSetsJson -Encoding utf8NoBOM

    $PodsJson = Invoke-NativeCommand -Label 'kubectl-get-rollout-pods' -Executable $Kubectl -Arguments @(
        '--context', $Context,
        '-n', $Namespace,
        'get', 'pods',
        '-l', 'app=payments',
        '-o', 'json'
    ) -TimeoutSeconds 30
    Set-Content -LiteralPath $PodsPath -Value $PodsJson -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Validate strict Deployment, ReplicaSet, and Pod ownership projection'
    $EffectArguments = @(
        'live', 'validate-effect',
        '--session', $SessionPath,
        '--persisted-response', $PatchResponsePath,
        '--after', $AfterPath,
        '--replica-sets', $ReplicaSetsPath,
        '--pods', $PodsPath,
        '--state-backend', $StateBackend
    )
    if ($StateBackend -eq 'postgres') {
        $EffectArguments += @('--postgres-url-env', $PostgresUrlEnv)
    }
    $EffectValidationJson = Invoke-NativeCommand -Label 'accordlock-live-validate-effect' -Executable $AccordLockExe -Arguments $EffectArguments -TimeoutSeconds 60
    $EffectValidation = $EffectValidationJson | ConvertFrom-Json -Depth 100
    if ($EffectValidation.schema_version -ne 2 `
        -or $EffectValidation.validation_kind -ne 'LOCAL_LIVE_KUBERNETES_EVENTUAL_EFFECT' `
        -or $EffectValidation.benchmark -ne $false `
        -or $EffectValidation.persisted_response_valid -ne $true `
        -or $EffectValidation.controller_projection_valid -ne $true `
        -or $EffectValidation.rollout_ownership_valid -ne $true `
        -or $EffectValidation.state_backend -ne $ExpectedSessionBackend `
        -or $EffectValidation.durable_consumption -ne $ExpectedDurability `
        -or $EffectValidation.state_records_reverified -ne $ExpectedDurability) {
        throw 'AccordLock emitted an eventual-effect report missing a required Deployment, ReplicaSet, or Pod ownership check.'
    }
    Set-Content -LiteralPath $EffectValidationPath -Value $EffectValidationJson -Encoding utf8NoBOM

    Start-RunnerStage -Name 'Record successful completion'
    if (-not (Test-Path -LiteralPath $CandidateValidationPath -PathType Leaf) `
        -or -not (Test-Path -LiteralPath $ValidationPath -PathType Leaf) `
        -or -not (Test-Path -LiteralPath $EffectValidationPath -PathType Leaf)) {
        throw "Success is impossible without candidate, persisted-response, and eventual-effect validation artifacts."
    }
    Write-RunEvent -Message "All validation and eventual-effect checks passed: $ValidationPath"
    Write-RunEvent -Message "All retained artifacts and diagnostics: $RunDirectory"
    Write-RunResult -Status 'success'
}
catch {
    $FailureMessage = Protect-SensitiveText -Text $_.Exception.Message
    Write-RunEvent -Message "FAILED during '$script:CurrentStage': $FailureMessage" -Level 'ERROR'
    Write-RunResult -Status 'failure' -ErrorMessage $FailureMessage
    if ($script:ClusterMutationStarted) {
        Write-RunEvent -Message "The named local cluster may have changed. It is retained for inspection; no automatic rollback or deletion was attempted." -Level 'WARN'
    }
    Write-RunEvent -Message "Failure diagnostics retained at: $RunDirectory" -Level 'ERROR'
    throw
}
