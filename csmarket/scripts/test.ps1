# csmarket/scripts/test.ps1
# Industrial test runner for Python projects (Windows PowerShell 5.1+ / PowerShell 7+)
# Goals:
# - Deterministic and CI-friendly test execution
# - Strict error handling and correct exit codes
# - Local and Docker execution modes
# - Standard artifacts: JUnit XML, coverage XML/HTML
# - Optional .env loading (without leaking secrets)

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("auto", "local", "docker")]
    [string]$Mode = "auto",

    [Parameter(Mandatory = $false)]
    [string]$ProjectRoot = "",

    [Parameter(Mandatory = $false)]
    [string]$Python = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("pytest", "python-m", "uv")]
    [string]$Runner = "pytest",

    [Parameter(Mandatory = $false)]
    [string]$VenvPath = "",

    [Parameter(Mandatory = $false)]
    [string]$EnvFile = ".env",

    [Parameter(Mandatory = $false)]
    [string]$TestsPath = "tests",

    [Parameter(Mandatory = $false)]
    [string[]]$PytestArgs = @(),

    [Parameter(Mandatory = $false)]
    [switch]$NoCoverage,

    [Parameter(Mandatory = $false)]
    [switch]$NoJUnit,

    [Parameter(Mandatory = $false)]
    [string]$ArtifactsDir = "artifacts\tests",

    [Parameter(Mandatory = $false)]
    [string]$DockerComposeFile = "docker-compose.yml",

    [Parameter(Mandatory = $false)]
    [string]$DockerService = "app",

    [Parameter(Mandatory = $false)]
    [switch]$FailFast,

    [Parameter(Mandatory = $false)]
    [switch]$Verbose,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet,

    [Parameter(Mandatory = $false)]
    [switch]$CI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("INFO", "WARN", "ERROR", "DEBUG")][string]$Level = "INFO"
    )
    if ($Quiet) { return }
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    if ($Level -eq "DEBUG" -and -not $Verbose) { return }
    Write-Host "$ts [$Level] $Message"
}

function Write-Fail {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Log -Message $Message -Level "ERROR"
}

function Resolve-ProjectRoot {
    param([string]$InputRoot)

    if ([string]::IsNullOrWhiteSpace($InputRoot)) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        return (Resolve-Path (Join-Path $scriptDir "..")).Path
    }

    return (Resolve-Path $InputRoot).Path
}

function Ensure-Dir {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Import-DotEnv {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$File
    )

    $envPath = Join-Path $Root $File
    if (-not (Test-Path -LiteralPath $envPath)) {
        Write-Log -Message "Env file not found, skipping: $envPath" -Level "DEBUG"
        return
    }

    Write-Log -Message "Loading env file: $envPath" -Level "INFO"

    $lines = Get-Content -LiteralPath $envPath -ErrorAction Stop
    foreach ($line in $lines) {
        $trim = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trim)) { continue }
        if ($trim.StartsWith("#")) { continue }

        $idx = $trim.IndexOf("=")
        if ($idx -lt 1) { continue }

        $key = $trim.Substring(0, $idx).Trim()
        $val = $trim.Substring($idx + 1).Trim()

        if ($val.StartsWith('"') -and $val.EndsWith('"') -and $val.Length -ge 2) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        if ($val.StartsWith("'") -and $val.EndsWith("'") -and $val.Length -ge 2) {
            $val = $val.Substring(1, $val.Length - 2)
        }

        if ([string]::IsNullOrWhiteSpace($key)) { continue }

        # Do not print values to avoid secret leaks
        [Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
}

function Find-Python {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $false)][string]$ExplicitPython,
        [Parameter(Mandatory = $false)][string]$ExplicitVenvPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPython)) {
        Write-Log -Message "Using explicit Python: $ExplicitPython" -Level "INFO"
        return $ExplicitPython
    }

    $venvCandidates = @()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitVenvPath)) {
        $venvCandidates += (Join-Path $Root $ExplicitVenvPath)
    } else {
        $venvCandidates += (Join-Path $Root ".venv")
        $venvCandidates += (Join-Path $Root "venv")
    }

    foreach ($vc in $venvCandidates) {
        $pyExe = Join-Path $vc "Scripts\python.exe"
        if (Test-Path -LiteralPath $pyExe) {
            Write-Log -Message "Using venv Python: $pyExe" -Level "INFO"
            return $pyExe
        }
    }

    foreach ($cmd in @("python", "py")) {
        try {
            $p = (Get-Command $cmd -ErrorAction Stop).Source
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Write-Log -Message "Using system Python command: $cmd ($p)" -Level "INFO"
                return $cmd
            }
        } catch {
            continue
        }
    }

    throw "Python not found. Provide -Python or create .venv/venv in project root."
}

function Exec-Native {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $false)][string[]]$Args = @(),
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        Push-Location $WorkingDirectory
    }
    try {
        Write-Log -Message ("Running: " + $File + " " + ($Args -join " ")) -Level "INFO"
        & $File @Args
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            throw "Command failed with exit code $code: $File"
        }
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            Pop-Location
        }
    }
}

function Detect-Mode {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RequestedMode
    )

    if ($RequestedMode -ne "auto") {
        return $RequestedMode
    }

    $composePath = Join-Path $Root $DockerComposeFile
    $hasCompose = Test-Path -LiteralPath $composePath

    $hasDocker = $false
    try {
        & docker version | Out-Null
        if ($LASTEXITCODE -eq 0) { $hasDocker = $true }
    } catch {
        $hasDocker = $false
    }

    if ($hasDocker -and $hasCompose) { return "docker" }
    return "local"
}

function Build-PytestArgs {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Artifacts,
        [Parameter(Mandatory = $true)][string]$Tests,
        [Parameter(Mandatory = $true)][switch]$DisableCoverage,
        [Parameter(Mandatory = $true)][switch]$DisableJUnit,
        [Parameter(Mandatory = $true)][switch]$IsCI,
        [Parameter(Mandatory = $true)][switch]$IsFailFast,
        [Parameter(Mandatory = $true)][switch]$IsVerbose,
        [Parameter(Mandatory = $true)][string[]]$ExtraArgs
    )

    $args = @()

    $testsPath = Join-Path $Root $Tests
    if (-not (Test-Path -LiteralPath $testsPath)) {
        throw "Tests path not found: $testsPath"
    }

    $args += $testsPath
    $args += "-ra"
    $args += "--strict-markers"

    if ($IsFailFast) {
        $args += "-x"
    }

    if ($IsVerbose) {
        $args += "-vv"
    }

    if ($IsCI) {
        $args += "--maxfail=1"
    }

    if (-not $DisableJUnit) {
        $junit = Join-Path $Artifacts "junit.xml"
        $args += "--junitxml=$junit"
    }

    if (-not $DisableCoverage) {
        $covXml = Join-Path $Artifacts "coverage.xml"
        $covHtml = Join-Path $Artifacts "htmlcov"

        $args += "--cov=."
        $args += "--cov-report=term-missing:skip-covered"
        $args += "--cov-report=xml:$covXml"
        $args += "--cov-report=html:$covHtml"
    }

    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) {
        $args += $ExtraArgs
    }

    return $args
}

function Run-Local {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$PyExe,
        [Parameter(Mandatory = $true)][string]$Artifacts
    )

    $pytestArgsFinal = Build-PytestArgs `
        -Root $Root `
        -Artifacts $Artifacts `
        -Tests $TestsPath `
        -DisableCoverage:$NoCoverage `
        -DisableJUnit:$NoJUnit `
        -IsCI:$CI `
        -IsFailFast:$FailFast `
        -IsVerbose:$Verbose `
        -ExtraArgs $PytestArgs

    if ($Runner -eq "python-m") {
        Exec-Native -File $PyExe -Args (@("-m", "pytest") + $pytestArgsFinal) -WorkingDirectory $Root
        return
    }

    if ($Runner -eq "uv") {
        try {
            $uv = (Get-Command "uv" -ErrorAction Stop).Source
        } catch {
            throw "Runner uv selected, but uv not found in PATH."
        }
        Exec-Native -File "uv" -Args (@("run", "pytest") + $pytestArgsFinal) -WorkingDirectory $Root
        return
    }

    # Runner pytest
    $pytest = ""
    try {
        $pytest = (Get-Command "pytest" -ErrorAction Stop).Source
    } catch {
        $pytest = ""
    }

    if (-not [string]::IsNullOrWhiteSpace($pytest)) {
        Exec-Native -File "pytest" -Args $pytestArgsFinal -WorkingDirectory $Root
        return
    }

    Exec-Native -File $PyExe -Args (@("-m", "pytest") + $pytestArgsFinal) -WorkingDirectory $Root
}

function Run-Docker {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Artifacts
    )

    $composePath = Join-Path $Root $DockerComposeFile
    if (-not (Test-Path -LiteralPath $composePath)) {
        throw "Docker compose file not found: $composePath"
    }

    $pytestArgsFinal = Build-PytestArgs `
        -Root $Root `
        -Artifacts $Artifacts `
        -Tests $TestsPath `
        -DisableCoverage:$NoCoverage `
        -DisableJUnit:$NoJUnit `
        -IsCI:$CI `
        -IsFailFast:$FailFast `
        -IsVerbose:$Verbose `
        -ExtraArgs $PytestArgs

    $cmdArgs = @(
        "compose",
        "-f", $composePath,
        "run",
        "--rm",
        $DockerService,
        "pytest"
    ) + $pytestArgsFinal

    Exec-Native -File "docker" -Args $cmdArgs -WorkingDirectory $Root
}

try {
    $root = Resolve-ProjectRoot -InputRoot $ProjectRoot
    Write-Log -Message "Project root: $root" -Level "INFO"

    $artifacts = Join-Path $root $ArtifactsDir
    Ensure-Dir -Path $artifacts
    Write-Log -Message "Artifacts dir: $artifacts" -Level "INFO"

    Import-DotEnv -Root $root -File $EnvFile

    $effectiveMode = Detect-Mode -Root $root -RequestedMode $Mode
    Write-Log -Message "Mode: $effectiveMode" -Level "INFO"

    if ($effectiveMode -eq "local") {
        $pyExe = Find-Python -Root $root -ExplicitPython $Python -ExplicitVenvPath $VenvPath
        Run-Local -Root $root -PyExe $pyExe -Artifacts $artifacts
    } elseif ($effectiveMode -eq "docker") {
        Run-Docker -Root $root -Artifacts $artifacts
    } else {
        throw "Unknown mode: $effectiveMode"
    }

    Write-Log -Message "Tests completed successfully." -Level "INFO"
    exit 0
} catch {
    Write-Fail -Message $_.Exception.Message
    if ($Verbose) {
        Write-Log -Message $_.ScriptStackTrace -Level "DEBUG"
    }
    exit 1
}
