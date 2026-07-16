<# 
csmarket/scripts/fmt.ps1

Industrial formatting entrypoint for Python projects (Ruff).
Designed for local dev and CI.

Behavior:
- Formats code via `ruff format`
- Optionally fixes lint via `ruff check --fix`
- Supports check-only mode for CI
- Works with Poetry or plain venv/system python

Exit codes:
0  Success
1  Formatting or linting failed, or prerequisites missing
#>

[CmdletBinding(PositionalBinding = $false)]
param(
  [Parameter(Mandatory = $false)]
  [string] $ProjectRoot = "",

  [Parameter(Mandatory = $false)]
  [string[]] $Targets = @("app", "tests"),

  [Parameter(Mandatory = $false)]
  [switch] $Check,

  [Parameter(Mandatory = $false)]
  [switch] $SkipLintFix,

  [Parameter(Mandatory = $false)]
  [switch] $UnsafeFixes,

  [Parameter(Mandatory = $false)]
  [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Log {
  param(
    [Parameter(Mandatory = $true)][string] $Message,
    [Parameter(Mandatory = $false)][ValidateSet("INFO","WARN","ERROR")][string] $Level = "INFO"
  )
  if ($Quiet) { return }

  $prefix = ""
  switch ($Level) {
    "INFO"  { $prefix = "[fmt][INFO] " }
    "WARN"  { $prefix = "[fmt][WARN] " }
    "ERROR" { $prefix = "[fmt][ERROR] " }
  }

  Write-Host ($prefix + $Message)
}

function Fail {
  param([Parameter(Mandatory = $true)][string] $Message)
  Write-Log -Level "ERROR" -Message $Message
  exit 1
}

function Resolve-ProjectRoot {
  param([string] $ExplicitRoot)

  if ($ExplicitRoot -and $ExplicitRoot.Trim().Length -gt 0) {
    $p = Resolve-Path -LiteralPath $ExplicitRoot -ErrorAction Stop
    return $p.Path
  }

  $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

  # Typical layout: csmarket/scripts/fmt.ps1 -> project root is one level up from scripts
  $candidate = Resolve-Path -LiteralPath (Join-Path $scriptDir "..") -ErrorAction Stop
  $candidatePath = $candidate.Path

  # If git is available, prefer git root for correctness
  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($null -ne $git) {
    try {
      $gitRoot = (& git -C $candidatePath rev-parse --show-toplevel 2>$null).Trim()
      if ($gitRoot -and (Test-Path -LiteralPath $gitRoot)) {
        return (Resolve-Path -LiteralPath $gitRoot).Path
      }
    } catch {
      # ignore and fallback
    }
  }

  return $candidatePath
}

function Test-Tool {
  param([Parameter(Mandatory = $true)][string] $Name)
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  return ($null -ne $cmd)
}

function Get-RuffRunner {
  param([Parameter(Mandatory = $true)][string] $Root)

  $hasPoetryLock = Test-Path -LiteralPath (Join-Path $Root "poetry.lock")
  $hasPyProject  = Test-Path -LiteralPath (Join-Path $Root "pyproject.toml")

  if (-not $hasPyProject) {
    Fail "pyproject.toml not found in project root: $Root"
  }

  if ($hasPoetryLock -and (Test-Tool "poetry")) {
    return @{
      Kind = "poetry"
      Exec = { param([string[]] $Args) & poetry run ruff @Args }
      Explain = "poetry run ruff"
    }
  }

  # Try local .venv first if present
  $venvPython = Join-Path $Root ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPython) {
    return @{
      Kind = "venv"
      Exec = { param([string[]] $Args) & $venvPython -m ruff @Args }
      Explain = ".venv python -m ruff"
    }
  }

  # Fallback to system python -m ruff
  if (Test-Tool "python") {
    return @{
      Kind = "python"
      Exec = { param([string[]] $Args) & python -m ruff @Args }
      Explain = "python -m ruff"
    }
  }

  # Last fallback: direct ruff on PATH
  if (Test-Tool "ruff") {
    return @{
      Kind = "ruff"
      Exec = { param([string[]] $Args) & ruff @Args }
      Explain = "ruff"
    }
  }

  Fail "No runnable Ruff found. Install Ruff or ensure Poetry/.venv/system Python is available."
}

function Invoke-Checked {
  param(
    [Parameter(Mandatory = $true)][scriptblock] $Runner,
    [Parameter(Mandatory = $true)][string[]] $Args,
    [Parameter(Mandatory = $true)][string] $What
  )

  Write-Log "$What: ruff $($Args -join ' ')" "INFO"

  & $Runner $Args
  $code = $LASTEXITCODE

  if ($code -ne 0) {
    Fail "$What failed with exit code $code"
  }
}

try {
  $root = Resolve-ProjectRoot -ExplicitRoot $ProjectRoot
  $root = (Resolve-Path -LiteralPath $root).Path

  Write-Log "Project root: $root" "INFO"

  $runnerInfo = Get-RuffRunner -Root $root
  Write-Log "Using runner: $($runnerInfo.Explain)" "INFO"

  Push-Location -LiteralPath $root

  # Validate targets exist; if none exist, default to current directory
  $resolvedTargets = New-Object System.Collections.Generic.List[string]
  foreach ($t in $Targets) {
    if ([string]::IsNullOrWhiteSpace($t)) { continue }
    $p = Join-Path $root $t
    if (Test-Path -LiteralPath $p) {
      $resolvedTargets.Add($t) | Out-Null
    }
  }
  if ($resolvedTargets.Count -eq 0) {
    $resolvedTargets.Add(".") | Out-Null
  }

  # Build args
  $formatArgs = New-Object System.Collections.Generic.List[string]
  $formatArgs.Add("format") | Out-Null
  if ($Check) { $formatArgs.Add("--check") | Out-Null }
  foreach ($t in $resolvedTargets) { $formatArgs.Add($t) | Out-Null }

  Invoke-Checked -Runner $runnerInfo.Exec -Args $formatArgs.ToArray() -What "Formatting"

  if (-not $SkipLintFix) {
    $checkArgs = New-Object System.Collections.Generic.List[string]
    $checkArgs.Add("check") | Out-Null
    if ($Check) {
      # In CI check mode we do not fix; we only verify
      foreach ($t in $resolvedTargets) { $checkArgs.Add($t) | Out-Null }
    } else {
      $checkArgs.Add("--fix") | Out-Null
      if ($UnsafeFixes) { $checkArgs.Add("--unsafe-fixes") | Out-Null }
      foreach ($t in $resolvedTargets) { $checkArgs.Add($t) | Out-Null }
    }

    $modeLabel = if ($Check) { "Lint check" } else { "Lint fix" }
    Invoke-Checked -Runner $runnerInfo.Exec -Args $checkArgs.ToArray() -What $modeLabel
  }

  Write-Log "Done" "INFO"
  exit 0
}
catch {
  Fail $_.Exception.Message
}
finally {
  try { Pop-Location | Out-Null } catch { }
}
