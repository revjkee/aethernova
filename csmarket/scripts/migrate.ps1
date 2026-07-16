# scripts/migrate.ps1
# Industrial Alembic migrations runner for Windows PowerShell 5.1+ and PowerShell 7+
# - Strict mode and fail-fast
# - Loads .env safely (optional)
# - Uses Poetry if available, otherwise uses local .venv or python from PATH
# - Supports common Alembic commands via a stable CLI

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("INFO", "WARN", "ERROR", "DEBUG")] [string] $Level,
        [Parameter(Mandatory = $true)][string] $Message
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message)
}

function Die {
    param([Parameter(Mandatory = $true)][string] $Message, [int] $Code = 1)
    Write-Log -Level "ERROR" -Message $Message
    exit $Code
}

function Get-RepoRoot {
    # Resolve repo root as: parent of scripts/ (this file is in scripts/)
    try {
        $scriptDir = Split-Path -Parent $PSCommandPath
        return (Resolve-Path (Join-Path $scriptDir "..")).Path
    } catch {
        Die "Cannot resolve repository root: $($_.Exception.Message)"
    }
}

function Import-DotEnv {
    param(
        [Parameter(Mandatory = $true)][string] $EnvPath
    )

    if (-not (Test-Path -LiteralPath $EnvPath -PathType Leaf)) {
        return
    }

    Write-Log -Level "INFO" -Message ("Loading environment from {0}" -f $EnvPath)

    $lines = Get-Content -LiteralPath $EnvPath -ErrorAction Stop
    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith("#")) { continue }

        # Support KEY=VALUE and export KEY=VALUE
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

        # Do not override already-set environment variables
        if ($null -eq [System.Environment]::GetEnvironmentVariable($key, "Process")) {
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

function Test-CommandExists {
    param([Parameter(Mandatory = $true)][string] $Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    return ($null -ne $cmd)
}

function Resolve-PythonRunner {
    param([Parameter(Mandatory = $true)][string] $RepoRoot)

    # Prefer Poetry if pyproject.toml exists and poetry is installed
    $pyproject = Join-Path $RepoRoot "pyproject.toml"
    if ((Test-Path -LiteralPath $pyproject -PathType Leaf) -and (Test-CommandExists "poetry")) {
        return @{
            Kind = "poetry"
            Exec = "poetry"
            PrefixArgs = @("run", "python")
        }
    }

    # Prefer local .venv if present
    $venvPythonCandidates = @(
        (Join-Path $RepoRoot ".venv\Scripts\python.exe"),
        (Join-Path $RepoRoot "venv\Scripts\python.exe")
    )

    foreach ($p in $venvPythonCandidates) {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            return @{
                Kind = "venv"
                Exec = $p
                PrefixArgs = @()
            }
        }
    }

    # Fallback to python from PATH
    if (Test-CommandExists "python") {
        return @{
            Kind = "path"
            Exec = "python"
            PrefixArgs = @()
        }
    }

    Die "Python runtime not found. Install Python, or create .venv, or install Poetry."
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)][hashtable] $Runner,
        [Parameter(Mandatory = $true)][string[]] $Args,
        [[string] $WorkingDirectory
    )

    $exec = $Runner.Exec
    $prefix = $Runner.PrefixArgs

    $fullArgs = @()
    $fullArgs += $prefix
    $fullArgs += $Args

    $wd = $WorkingDirectory
    if ([string]::IsNullOrWhiteSpace($wd)) {
        $wd = (Get-Location).Path
    }

    Write-Log -Level "DEBUG" -Message ("Exec: {0} {1}" -f $exec, ($fullArgs -join " "))
    $p = Start-Process -FilePath $exec -ArgumentList $fullArgs -WorkingDirectory $wd -NoNewWindow -PassThru -Wait
    if ($p.ExitCode -ne 0) {
        Die ("Command failed with exit code {0}" -f $p.ExitCode) $p.ExitCode
    }
}

function Show-Help {
@"
Usage:
  pwsh -File scripts/migrate.ps1 <command> [options]

Commands:
  upgrade <revision>           Apply migrations up to revision (default: head)
  downgrade <revision>         Revert migrations down to revision
  revision -m <message>        Create new revision (supports --autogenerate)
  current                      Show current revision
  history                      Show migration history
  heads                        Show heads
  stamp <revision>             Stamp database with revision (no migration)
  check                        Run alembic check (where supported)
  init                         Validate configuration and runtime

Global options:
  --env <path>                 Path to .env file (default: <repoRoot>\.env if exists, else <repoRoot>\.env.example not loaded)
  --cwd <path>                 Working directory for running commands (default: repoRoot)

Examples:
  pwsh -File scripts/migrate.ps1 upgrade head
  pwsh -File scripts/migrate.ps1 downgrade -1
  pwsh -File scripts/migrate.ps1 revision -m "init" --autogenerate
"@
}

try {
    $repoRoot = Get-RepoRoot

    $command = $null
    $rest = @()

    if ($args.Count -ge 1) {
        $command = [string]$args[0]
        if ($args.Count -gt 1) {
            $rest = $args[1..($args.Count - 1)]
        }
    }

    if ([string]::IsNullOrWhiteSpace($command) -or $command -in @("-h", "--help", "help")) {
        Show-Help
        exit 0
    }

    # Parse global options: --env, --cwd
    $envPath = $null
    $cwd = $repoRoot

    $parsed = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $rest.Count; $i++) {
        $tok = $rest[$i]
        if ($tok -eq "--env") {
            if ($i + 1 -ge $rest.Count) { Die "--env requires a value" }
            $envPath = [string]$rest[$i + 1]
            $i++
            continue
        }
        if ($tok -eq "--cwd") {
            if ($i + 1 -ge $rest.Count) { Die "--cwd requires a value" }
            $cwd = [string]$rest[$i + 1]
            $i++
            continue
        }
        $parsed.Add([string]$tok) | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($envPath)) {
        $defaultEnv = Join-Path $repoRoot ".env"
        if (Test-Path -LiteralPath $defaultEnv -PathType Leaf) {
            $envPath = $defaultEnv
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        Import-DotEnv -EnvPath $envPath
    }

    if (-not (Test-Path -LiteralPath $cwd -PathType Container)) {
        Die ("Working directory does not exist: {0}" -f $cwd)
    }

    $runner = Resolve-PythonRunner -RepoRoot $repoRoot

    Write-Log -Level "INFO" -Message ("RepoRoot: {0}" -f $repoRoot)
    Write-Log -Level "INFO" -Message ("Runner: {0}" -f $runner.Kind)
    Write-Log -Level "INFO" -Message ("Cwd: {0}" -f $cwd)

    # Ensure alembic.ini exists somewhere in cwd or repoRoot
    $alembicIniCands = @(
        (Join-Path $cwd "alembic.ini"),
        (Join-Path $repoRoot "alembic.ini")
    )
    $hasAlembicIni = $false
    foreach ($c in $alembicIniCands) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { $hasAlembicIni = $true; break }
    }
    if (-not $hasAlembicIni) {
        Write-Log -Level "WARN" -Message "alembic.ini not found in cwd or repoRoot. Alembic may rely on alternative configuration."
    }

    $alembicArgs = @("-m", "alembic")
    switch ($command.ToLowerInvariant()) {
        "upgrade" {
            $rev = "head"
            if ($parsed.Count -ge 1) { $rev = $parsed[0] }
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("upgrade", $rev)) -WorkingDirectory $cwd
        }
        "downgrade" {
            if ($parsed.Count -lt 1) { Die "downgrade requires <revision>" }
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("downgrade", $parsed[0])) -WorkingDirectory $cwd
        }
        "revision" {
            if ($parsed.Count -lt 2) {
                # Need at least: -m <message>
                # Allow passing through all args, but enforce message exists for industrial consistency
                Die "revision requires at least: -m <message> (and optional --autogenerate)"
            }
            # Pass through everything after "revision" to alembic
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("revision") + @($parsed.ToArray())) -WorkingDirectory $cwd
        }
        "current" {
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("current")) -WorkingDirectory $cwd
        }
        "history" {
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("history")) -WorkingDirectory $cwd
        }
        "heads" {
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("heads")) -WorkingDirectory $cwd
        }
        "stamp" {
            if ($parsed.Count -lt 1) { Die "stamp requires <revision>" }
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("stamp", $parsed[0])) -WorkingDirectory $cwd
        }
        "check" {
            # alembic check exists in newer Alembic versions; if not available, command will fail and return code
            Invoke-Python -Runner $runner -Args ($alembicArgs + @("check")) -WorkingDirectory $cwd
        }
        "init" {
            # Dry validation: can import alembic and print version
            $py = @(
                "-c",
                "import sys; import alembic; print('alembic', alembic.__version__); sys.exit(0)"
            )
            Invoke-Python -Runner $runner -Args $py -WorkingDirectory $cwd
        }
        default {
            Die ("Unknown command: {0}" -f $command)
        }
    }

    Write-Log -Level "INFO" -Message "Done"
    exit 0
} catch {
    Die ("Unhandled error: {0}" -f $_.Exception.Message) 1
}
