$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $projectRoot
try {
    $leanSources = Get-ChildItem -Path $projectRoot -Recurse -Filter "*.lean" -File
    $forbidden = @($leanSources | Select-String -Pattern "\b(sorry|axiom)\b")
    if ($forbidden.Count -ne 0) {
        throw "Forbidden proof placeholder found:`n$forbidden"
    }

    $lakeCommand = $null
    if ($env:ACCORDLOCK_LAKE) {
        $configuredLake = [System.IO.Path]::GetFullPath($env:ACCORDLOCK_LAKE)
        if (-not (Test-Path -LiteralPath $configuredLake -PathType Leaf)) {
            throw "ACCORDLOCK_LAKE does not name a regular file."
        }
        $lakeCommand = $configuredLake
    }
    elseif ($env:USERPROFILE) {
        $toolchainId = (Get-Content -LiteralPath (Join-Path $projectRoot "lean-toolchain") -Raw).Trim()
        $toolchainDirectory = $toolchainId.Replace("/", "--").Replace(":", "---")
        $installedLake = Join-Path $env:USERPROFILE ".elan\toolchains\$toolchainDirectory\bin\lake.exe"
        if (Test-Path -LiteralPath $installedLake -PathType Leaf) {
            $lakeCommand = $installedLake
        }
    }
    if (-not $lakeCommand) {
        $lakeCommand = "lake"
    }

    & $lakeCommand build
    if ($LASTEXITCODE -ne 0) {
        throw "Lean build failed."
    }

    $theoremCount = @($leanSources | Select-String -Pattern "^theorem ").Count
    Write-Host "Verified $theoremCount theorems; no forbidden proof placeholders found."
}
finally {
    Pop-Location
}
