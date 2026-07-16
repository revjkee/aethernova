# scripts/dev.ps1
# Industrial dev runner for csmarket (Windows PowerShell 7+ recommended)
# Supports:
#   - Local dev: venv + deps + uvicorn --reload
#   - Docker dev: docker compose up
#   - .env loading (process-scoped)
#   - Strict validation, consistent logging, safe exit codes

[CmdletBinding()]
param(
  [ValidateSet("local", "docker")]
  [string]$Mode = "local",

  [string]$ProjectRoot = "",

  [string]$AppModule = "app.main:app",

  [string]$Host = "127.0.0.1",
  [int]$Port = 8000,

  [string]$EnvFile = ".env",
  [string]$EnvExampleFile = ".env.example",

  [string]$VenvDir = ".venv",

  [ValidateSet("uv", "pip", "skip")]
  [string]$InstallDeps = "uv",

  [switch]$RecreateVenv,

  [ValidateSet("docker-compose.yml", "compose.yaml", "compose.yml")]
  [string]$ComposeFile = "docker-compose.yml",

  [string]$ComposeProjectName = "csmarket",

  [switch]$Detach,
  [switch]$Build,
  [switch]$DownOnExit,
  [switch]$NoEnvLoad,

  [switch]$VerboseLogs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSStyle.OutputRendering = "PlainText"

function Write-Log {
  param(
    [ValidateSet("INFO","WARN","ERROR","DEBUG")]
    [string]$Level,
    [Parameter(Mandatory=$true)][string]$Message
  )
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  if ($Level -eq "DEBUG" -and -not $VerboseLogs) { return }
  $prefix = "[$ts] [$Level]"
  if ($Level -eq "ERROR") { Write-Error "$prefix $Message"; return }
  if ($Level -eq "WARN")  { Write-Warning "$prefix $Message"; return }
  Write-Host "$prefix $Message"
}

function Fail {
  param([string]$Message, [int]$Code = 1)
  Write-Log -Level "ERROR" -Message $Message
  exit $Code
}

function Assert-Command {
  param([string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Fail "Required command not found in PATH: $Name"
  }
}

function Resolve-ProjectRoot {
  param([string]$RootArg)

  if ([string]::IsNullOrWhiteSpace($RootArg)) {
    # Assume script is in <root>\scripts\dev.ps1
    $scriptDir = Split-Path -Parent $PSCommandPath
    $candidate = Split-Path -Parent $scriptDir
    return (Resolve-Path $candidate).Path
  }

  if (-not (Test-Path -LiteralPath $RootArg)) {
    Fail "ProjectRoot path does not exist: $RootArg"
  }

  return (Resolve-Path $RootArg).Path
}

function Load-DotEnv {
  param([string]$FilePath)

  if ($NoEnvLoad) {
    Write-Log -Level "INFO" -Message "Skipping .env loading (NoEnvLoad enabled)."
    return
  }

  if (-not (Test-Path -LiteralPath $FilePath)) {
    if (Test-Path -LiteralPath $EnvExampleFile) {
      Write-Log -Level "WARN" -Message "Env file not found: $FilePath. Example exists: $EnvExampleFile"
    } else {
      Write-Log -Level "WARN" -Message "Env file not found: $FilePath"
    }
    return
  }

  Write-Log -Level "INFO" -Message "Loading environment variables from: $FilePath"
  $lines = Get-Content -LiteralPath $FilePath -ErrorAction Stop

  foreach ($raw in $lines) {
    $line = $raw.Trim()
    if ($line.Length -eq 0) { continue }
    if ($line.StartsWith("#")) { continue }

    # Support "export KEY=VALUE" and "KEY=VALUE"
    if ($line.StartsWith("export ")) {
      $line = $line.Substring(7).Trim()
    }

    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { continue }

    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()

    # Strip optional surrounding quotes
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }

    if ([string]::IsNullOrWhiteSpace($key)) { continue }

    # Process-scoped env (does not persist on machine)
    [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
  }
}

function Ensure-Venv {
  param([string]$Root, [string]$VenvPath, [switch]$ForceRecreate)

  $fullVenv = Join-Path $Root $VenvPath
  $pythonCmd = $null

  Assert-Command "python"

  if ($ForceRecreate -and (Test-Path -LiteralPath $fullVenv)) {
    Write-Log -Level "WARN" -Message "Recreating venv: removing $fullVenv"
    Remove-Item -LiteralPath $fullVenv -Recurse -Force -ErrorAction Stop
  }

  if (-not (Test-Path -LiteralPath $fullVenv)) {
    Write-Log -Level "INFO" -Message "Creating venv in: $fullVenv"
    & python -m venv $fullVenv
  } else {
    Write-Log -Level "INFO" -Message "Using existing venv: $fullVenv"
  }

  $venvPython = Join-Path $fullVenv "Scripts\python.exe"
  if (-not (Test-Path -LiteralPath $venvPython)) {
    Fail "Venv python not found at expected path: $venvPython"
  }

  return $venvPython
}

function Install-Dependencies {
  param([string]$Root, [string]$VenvPython, [string]$Strategy)

  if ($Strategy -eq "skip") {
    Write-Log -Level "INFO" -Message "Skipping dependency installation (InstallDeps=skip)."
    return
  }

  # Common dependency sources: pyproject.toml (preferred), requirements.txt (fallback)
  $pyproject = Join-Path $Root "pyproject.toml"
  $requirements = Join-Path $Root "requirements.txt"

  if (Test-Path -LiteralPath $pyproject) {
    if ($Strategy -eq "uv") {
      if (Get-Command "uv" -ErrorAction SilentlyContinue) {
        Write-Log -Level "INFO" -Message "Installing deps from pyproject.toml via uv"
        & uv sync --project $Root
        return
      } else {
        Write-Log -Level "WARN" -Message "uv not found, falling back to pip"
        $Strategy = "pip"
      }
    }

    if ($Strategy -eq "pip") {
      Write-Log -Level "INFO" -Message "Installing deps from pyproject.toml via pip (PEP 517/518)"
      & $VenvPython -m pip install --upgrade pip wheel setuptools
      & $VenvPython -m pip install -e $Root
      return
    }
  }

  if (Test-Path -LiteralPath $requirements) {
    Write-Log -Level "INFO" -Message "Installing deps from requirements.txt via pip"
    & $VenvPython -m pip install --upgrade pip wheel setuptools
    & $VenvPython -m pip install -r $requirements
    return
  }

  Write-Log -Level "WARN" -Message "No pyproject.toml or requirements.txt found. Dependencies not installed."
}

function Start-LocalDev {
  param([string]$Root)

  Push-Location $Root
  try {
    Load-DotEnv -FilePath (Join-Path $Root $EnvFile)

    $venvPython = Ensure-Venv -Root $Root -VenvPath $VenvDir -ForceRecreate:$RecreateVenv
    Install-Dependencies -Root $Root -VenvPython $venvPython -Strategy $InstallDeps

    # Prefer uvicorn module resolution from venv
    Write-Log -Level "INFO" -Message "Starting local dev server: $AppModule on $Host:$Port"
    Write-Log -Level "INFO" -Message "Press Ctrl+C to stop."

    & $venvPython -m uvicorn $AppModule --host $Host --port $Port --reload
  }
  finally {
    Pop-Location
  }
}

function Get-DockerComposeArgs {
  param([string]$Root)

  $composePath = Join-Path $Root $ComposeFile
  if (-not (Test-Path -LiteralPath $composePath)) {
    Fail "Compose file not found: $composePath"
  }

  # Prefer "docker compose" (v2). If not available, fall back to "docker-compose"
  $dockerComposeIsV2 = $false
  if (Get-Command "docker" -ErrorAction SilentlyContinue) {
    $dockerComposeIsV2 = $true
  }

  if ($dockerComposeIsV2) {
    return @{
      Cmd = "docker"
      BaseArgs = @("compose", "-p", $ComposeProjectName, "-f", $composePath)
    }
  }

  if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
    return @{
      Cmd = "docker-compose"
      BaseArgs = @("-p", $ComposeProjectName, "-f", $composePath)
    }
  }

  Fail "Neither docker (with compose) nor docker-compose found."
}

function Start-DockerDev {
  param([string]$Root)

  Assert-Command "docker"

  Push-Location $Root
  try {
    if (-not $NoEnvLoad) {
      # For docker compose, .env is usually read automatically when in working directory,
      # but we still load to keep process consistent for any scripts reading env.
      Load-DotEnv -FilePath (Join-Path $Root $EnvFile)
    }

    $dc = Get-DockerComposeArgs -Root $Root
    $cmd = $dc.Cmd
    $base = $dc.BaseArgs

    $upArgs = @()
    $upArgs += $base
    $upArgs += @("up")

    if ($Build) { $upArgs += @("--build") }
    if ($Detach) { $upArgs += @("-d") }

    Write-Log -Level "INFO" -Message "Starting docker dev with $ComposeFile (project $ComposeProjectName)"
    Write-Log -Level "INFO" -Message "Command: $cmd $($upArgs -join ' ')"

    & $cmd @upArgs

    if (-not $Detach) {
      Write-Log -Level "INFO" -Message "Attached mode. Press Ctrl+C to stop."
    }

    if ($DownOnExit) {
      Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action {
        try {
          Write-Host "[INFO] Shutting down docker compose (DownOnExit enabled)"
          & $using:cmd @($using:base + @("down", "--remove-orphans"))
        } catch {}
      } | Out-Null
    }
  }
  finally {
    Pop-Location
  }
}

# Main
$root = Resolve-ProjectRoot -RootArg $ProjectRoot

Write-Log -Level "INFO" -Message "csmarket dev runner"
Write-Log -Level "INFO" -Message "Mode: $Mode"
Write-Log -Level "INFO" -Message "ProjectRoot: $root"

switch ($Mode) {
  "local" { Start-LocalDev -Root $root }
  "docker" { Start-DockerDev -Root $root }
  default { Fail "Unsupported mode: $Mode" }
}
