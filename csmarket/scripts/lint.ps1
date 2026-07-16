<#PSScriptInfo
.VERSION 1.0.0
.GUID 3b0c1d2c-8e9c-4d31-9c20-7e2d9dbe7f8c
.AUTHOR csmarket
.COPYRIGHT (c) csmarket
.TAGS lint ruff mypy ci
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
Industrial lint runner for csmarket.
#>

<#
.SYNOPSIS
Industrial lint script for csmarket (PowerShell).

.DESCRIPTION
Runs Ruff lint and Ruff formatting check in a deterministic, CI-friendly way.
Optionally runs mypy if enabled or available.

.PARAMETER ProjectRoot
Project root path (defaults to repository root inferred from this script location).

.PARAMETER Path
Path(s) to lint (defaults to "app" and "tests" if they exist, otherwise ProjectRoot).

.PARAMETER Fix
Apply safe fixes via `ruff check --fix`.

.PARAMETER UnsafeFix
Apply unsafe fixes via `ruff check --unsafe-fixes`.

.PARAMETER Mypy
Run mypy (if installed). If not installed, fails only when -Mypy is explicitly provided.

.PARAMETER StrictMypy
If set, mypy failures fail the script (default true when -Mypy is provided). If -Mypy is not provided,
mypy is best-effort and does not fail the script if missing.

.PARAMETER NoFormatCheck
Skip `ruff format --check`.

.PARAMETER NoRuffCheck
Skip `ruff check`.

.PARAMETER ExtraRuffArgs
Additional arguments passed to `ruff check` as-is.

.PARAMETER ExtraFormatArgs
Additional arguments passed to `ruff format` as-is.

.PARAMETER CI
Force CI behavior (non-interactive, stable output). Default auto-detect by common env vars.

.EXAMPLE
pwsh -File scripts/lint.ps1

.EXAMPLE
pwsh -File scripts/lint.ps1 -Fix

.EXAMPLE
pwsh -File scripts/lint.ps1 -Mypy -StrictMypy
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ProjectRoot,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Path,

    [Parameter(Mandatory = $false)]
    [switch] $Fix,

    [Parameter(Mandatory = $false)]
    [switch] $UnsafeFix,

    [Parameter(Mandatory = $false)]
    [switch] $Mypy,

    [Parameter(Mandatory = $false)]
    [switch] $StrictMypy,

    [Parameter(Mandatory = $false)]
    [switch] $NoFormatCheck,

    [Parameter(Mandatory = $false)]
    [switch] $NoRuffCheck,

    [Parameter(Mandatory = $false)]
    [string[]] $ExtraRuffArgs = @(),

    [Parameter(Mandatory = $false)]
    [string[]] $ExtraFormatArgs = @(),

    [Parameter(Mandatory = $false)]
    [switch] $CI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$PSNativeCommandUseErrorActionPreference = $true

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $Message,
        [Parameter(Mandatory = $false)][ValidateSet("INFO","WARN","ERROR")][string] $Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
    Write-Host "[$ts] [$Level] $Message"
}

function Resolve-ProjectRoot {
    param([string] $Candidate)

    if (-not [string]::IsNullOrWhiteSpace($Candidate)) {
        $full = (Resolve-Path -Path $Candidate).Path
        return $full
    }

    $scriptDir = Split-Path -Parent $PSCommandPath
    # Assume scripts/ lives under project root.
    $root = Split-Path -Parent $scriptDir

    if (Test-Path -Path (Join-Path $root "pyproject.toml")) { return $root }
    if (Test-Path -Path (Join-Path $root ".git")) { return $root }

    # Fallback: walk up to find pyproject.toml or .git
    $current = $scriptDir
    for ($i = 0; $i -lt 8; $i++) {
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
        if (Test-Path -Path (Join-Path $parent "pyproject.toml")) { return $parent }
        if (Test-Path -Path (Join-Path $parent ".git")) { return $parent }
        $current = $parent
    }

    return (Resolve-Path -Path $root).Path
}

function Get-DefaultTargets {
    param([string] $Root)

    $targets = New-Object System.Collections.Generic.List[string]
    $app = Join-Path $Root "app"
    $tests = Join-Path $Root "tests"

    if (Test-Path -Path $app) { [void]$targets.Add($app) }
    if (Test-Path -Path $tests) { [void]$targets.Add($tests) }

    if ($targets.Count -eq 0) {
        [void]$targets.Add($Root)
    }

    return $targets.ToArray()
}

function Resolve-VenvBin {
    param([string] $Root)

    $venv = Join-Path $Root ".venv"
    if (-not (Test-Path -Path $venv)) { return $null }

    $isWindows = $PSVersionTable.Platform -eq "Win32NT"
    if ($isWindows) {
        $bin = Join-Path $venv "Scripts"
    } else {
        $bin = Join-Path $venv "bin"
    }

    if (Test-Path -Path $bin) { return $bin }
    return $null
}

function Find-Tool {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $Name,
        [Parameter(Mandatory = $false)][string] $PreferredBin
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredBin)) {
        $candidate = Join-Path $PreferredBin $Name
        if ($PSVersionTable.Platform -eq "Win32NT") { $candidate = "$candidate.exe" }
        if (Test-Path -Path $candidate) { return (Resolve-Path -Path $candidate).Path }
    }

    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    return $null
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $Exe,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]] $Args,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $What
    )

    Write-Log "$What: $Exe $($Args -join ' ')" "INFO"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $Exe
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    foreach ($a in $Args) { [void]$pinfo.ArgumentList.Add($a) }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo

    $null = $proc.Start()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if (-not [string]::IsNullOrWhiteSpace($stdout)) { Write-Host $stdout.TrimEnd() }
    if (-not [string]::IsNullOrWhiteSpace($stderr)) { Write-Host $stderr.TrimEnd() }

    if ($proc.ExitCode -ne 0) {
        throw "$What failed with exit code $($proc.ExitCode)."
    }
}

# CI detection
$ciDetected = $CI.IsPresent -or
    ($env:CI -eq "true") -or ($env:GITHUB_ACTIONS -eq "true") -or ($env:GITLAB_CI -eq "true") -or
    ($env:TF_BUILD -eq "True") -or ($env:BUILD_BUILDID) -or ($env:BUILDKITE) -or ($env:CIRCLECI -eq "true")

$root = Resolve-ProjectRoot -Candidate $ProjectRoot
$root = (Resolve-Path -Path $root).Path
Set-Location -Path $root

Write-Log "Project root: $root" "INFO"

$targets = @()
if ($null -ne $Path -and $Path.Count -gt 0) {
    foreach ($p in $Path) {
        $rp = (Resolve-Path -Path $p -ErrorAction Stop).Path
        $targets += $rp
    }
} else {
    $targets = Get-DefaultTargets -Root $root
}

Write-Log "Targets: $($targets -join ', ')" "INFO"

$venvBin = Resolve-VenvBin -Root $root
if ($null -ne $venvBin) {
    Write-Log "Using venv bin: $venvBin" "INFO"
} else {
    Write-Log "No .venv detected, using system PATH" "WARN"
}

$ruffExe = Find-Tool -Name "ruff" -PreferredBin $venvBin
if ($null -eq $ruffExe -and -not $NoRuffCheck.IsPresent -or -not $NoFormatCheck.IsPresent) {
    throw "ruff not found. Install it in .venv or system environment."
}

$mypyExe = Find-Tool -Name "mypy" -PreferredBin $venvBin

# Execute
try {
    if (-not $NoRuffCheck.IsPresent) {
        $ruffArgs = New-Object System.Collections.Generic.List[string]
        [void]$ruffArgs.Add("check")

        if ($Fix.IsPresent) { [void]$ruffArgs.Add("--fix") }
        if ($UnsafeFix.IsPresent) { [void]$ruffArgs.Add("--unsafe-fixes") }

        if ($ciDetected) {
            # Stable, parsable-ish output; do not rely on color.
            [void]$ruffArgs.Add("--no-cache")
        }

        foreach ($a in $ExtraRuffArgs) { [void]$ruffArgs.Add($a) }

        foreach ($t in $targets) { [void]$ruffArgs.Add($t) }

        Invoke-Tool -Exe $ruffExe -Args $ruffArgs.ToArray() -What "Ruff check"
        Write-Log "Ruff check passed" "INFO"
    } else {
        Write-Log "Skipping Ruff check (NoRuffCheck set)" "WARN"
    }

    if (-not $NoFormatCheck.IsPresent) {
        $fmtArgs = New-Object System.Collections.Generic.List[string]
        [void]$fmtArgs.Add("format")
        [void]$fmtArgs.Add("--check")

        if ($ciDetected) {
            [void]$fmtArgs.Add("--no-cache")
        }

        foreach ($a in $ExtraFormatArgs) { [void]$fmtArgs.Add($a) }
        foreach ($t in $targets) { [void]$fmtArgs.Add($t) }

        Invoke-Tool -Exe $ruffExe -Args $fmtArgs.ToArray() -What "Ruff format check"
        Write-Log "Ruff format check passed" "INFO"
    } else {
        Write-Log "Skipping Ruff format check (NoFormatCheck set)" "WARN"
    }

    $runMypy = $Mypy.IsPresent
    if ($runMypy) {
        if ($null -eq $mypyExe) {
            throw "mypy not found, but -Mypy was provided."
        }

        $mypyArgs = New-Object System.Collections.Generic.List[string]
        if ($ciDetected) {
            # Avoid incremental cache surprises in CI.
            [void]$mypyArgs.Add("--no-incremental")
        }

        # Prefer config from pyproject.toml if present.
        foreach ($t in $targets) { [void]$mypyArgs.Add($t) }

        Invoke-Tool -Exe $mypyExe -Args $mypyArgs.ToArray() -What "mypy"
        Write-Log "mypy passed" "INFO"
    } else {
        # Best-effort mypy if installed and explicitly requested by policy can be added later.
        if ($null -ne $mypyExe -and $StrictMypy.IsPresent) {
            # If someone sets StrictMypy without Mypy, treat as explicit intent.
            $mypyArgs = New-Object System.Collections.Generic.List[string]
            if ($ciDetected) { [void]$mypyArgs.Add("--no-incremental") }
            foreach ($t in $targets) { [void]$mypyArgs.Add($t) }
            Invoke-Tool -Exe $mypyExe -Args $mypyArgs.ToArray() -What "mypy"
            Write-Log "mypy passed" "INFO"
        } else {
            Write-Log "mypy not requested" "INFO"
        }
    }

    Write-Log "Lint completed successfully" "INFO"
    exit 0
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    exit 1
}
finally {
    Set-Location -Path $root
}
