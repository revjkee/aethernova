# File: csmarket/scripts/e2e.ps1
# Purpose: Industrial end-to-end test runner for csmarket using Docker Compose
# Requirements: Docker Desktop / Engine, docker compose v2+, PowerShell 5.1+ or 7+
# Notes:
# - Uses strict error handling
# - Collects artifacts (compose logs, inspect, health diagnostics)
# - Waits for service readiness (HTTP health endpoint and/or container healthcheck)

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath "..")).Path,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ComposeFile = "",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ComposeProjectName = "csmarket-e2e",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ComposeProfile = "e2e",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ServiceName = "api",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$HealthUrl = "http://127.0.0.1:8000/health",

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 3600)]
  [int]$StartupTimeoutSec = 180,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 30)]
  [int]$HealthPollIntervalSec = 2,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ArtifactsDir = "",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$EnvFile = ".env",

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$E2ECommand = "python -m pytest -q -m e2e --maxfail=1",

  [Parameter(Mandatory = $false)]
  [ValidateSet("Always", "OnFailure", "Never")]
  [string]$DumpLogs = "OnFailure",

  [Parameter(Mandatory = $false)]
  [switch]$NoDown,

  [Parameter(Mandatory = $false)]
  [switch]$NoBuild,

  [Parameter(Mandatory = $false)]
  [switch]$Pull,

  [Parameter(Mandatory = $false)]
  [switch]$VerboseDocker
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Write-Log {
  param(
    [Parameter(Mandatory = $true)][string]$Message,
    [Parameter(Mandatory = $false)][ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
  )
  $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
  Write-Host "[$ts][$Level] $Message"
}

function Assert-Command {
  param([Parameter(Mandatory = $true)][string]$Name)
  $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
  if (-not $cmd) {
    throw "Required command not found: $Name"
  }
}

function New-Dir {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Exec {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $false)][string]$WorkingDirectory = ""
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.Arguments = ($Arguments -join " ")
  if ($WorkingDirectory -and $WorkingDirectory.Trim().Length -gt 0) {
    $psi.WorkingDirectory = $WorkingDirectory
  }
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi

  $null = $p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  return [pscustomobject]@{
    ExitCode = $p.ExitCode
    StdOut   = $stdout
    StdErr   = $stderr
  }
}

function Resolve-ComposeFile {
  param([Parameter(Mandatory = $true)][string]$Root)

  if ($ComposeFile -and $ComposeFile.Trim().Length -gt 0) {
    $resolved = (Resolve-Path -LiteralPath $ComposeFile).Path
    return $resolved
  }

  $candidates = @(
    (Join-Path -Path $Root -ChildPath "docker-compose.yml"),
    (Join-Path -Path $Root -ChildPath "docker-compose.e2e.yml"),
    (Join-Path -Path $Root -ChildPath "compose.yml")
  )

  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) {
      return (Resolve-Path -LiteralPath $c).Path
    }
  }

  throw "Compose file not found. Provide -ComposeFile or place docker-compose.yml in project root: $Root"
}

function ComposeArgsBase {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ComposePath
  )

  $args = @("compose", "--project-name", $ComposeProjectName, "--file", "`"$ComposePath`"")

  $envPath = Join-Path -Path $Root -ChildPath $EnvFile
  if (Test-Path -LiteralPath $envPath) {
    $args += @("--env-file", "`"$envPath`"")
  }

  if ($ComposeProfile -and $ComposeProfile.Trim().Length -gt 0) {
    $args += @("--profile", $ComposeProfile)
  }

  if ($VerboseDocker) {
    $args += @("--verbose")
  }

  return $args
}

function Save-TextFileUtf8NoBom {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Content
  )
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Try-HttpHealth {
  param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][int]$IntervalSec
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 5 -UseBasicParsing
      if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) {
        if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
          return $true
        }
      }
    } catch {
      # ignore
    }
    Start-Sleep -Seconds $IntervalSec
  }
  return $false
}

function Get-ComposeContainerId {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ComposePath,
    [Parameter(Mandatory = $true)][string]$Svc
  )
  $base = ComposeArgsBase -Root $Root -ComposePath $ComposePath
  $args = $base + @("ps", "-q", $Svc)
  $r = Exec -FilePath "docker" -Arguments $args -WorkingDirectory $Root
  if ($r.ExitCode -ne 0) {
    throw "Failed to get container id for service '$Svc': $($r.StdErr)"
  }
  $id = ($r.StdOut -split "`r?`n" | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -First 1)
  if (-not $id) {
    return ""
  }
  return $id.Trim()
}

function Try-ContainerHealth {
  param(
    [Parameter(Mandatory = $true)][string]$ContainerId,
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][int]$IntervalSec
  )
  if (-not $ContainerId -or $ContainerId.Trim().Length -eq 0) {
    return $false
  }

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $inspect = Exec -FilePath "docker" -Arguments @("inspect", $ContainerId)
    if ($inspect.ExitCode -eq 0) {
      try {
        $json = $inspect.StdOut | ConvertFrom-Json
        $state = $json[0].State
        if ($state -and $state.Health -and $state.Health.Status) {
          if ($state.Health.Status -eq "healthy") {
            return $true
          }
          if ($state.Health.Status -eq "unhealthy") {
            return $false
          }
        } else {
          # No healthcheck defined, treat as not supported
          return $false
        }
      } catch {
        # ignore parse errors
      }
    }
    Start-Sleep -Seconds $IntervalSec
  }

  return $false
}

function Dump-Diagnostics {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ComposePath,
    [Parameter(Mandatory = $true)][string]$Artifacts
  )

  try {
    $base = ComposeArgsBase -Root $Root -ComposePath $ComposePath

    $ps = Exec -FilePath "docker" -Arguments ($base + @("ps")) -WorkingDirectory $Root
    Save-TextFileUtf8NoBom -Path (Join-Path $Artifacts "compose_ps.txt") -Content ($ps.StdOut + "`n" + $ps.StdErr)

    $logs = Exec -FilePath "docker" -Arguments ($base + @("logs", "--no-color")) -WorkingDirectory $Root
    Save-TextFileUtf8NoBom -Path (Join-Path $Artifacts "compose_logs.txt") -Content ($logs.StdOut + "`n" + $logs.StdErr)

    $id = Get-ComposeContainerId -Root $Root -ComposePath $ComposePath -Svc $ServiceName
    if ($id) {
      $insp = Exec -FilePath "docker" -Arguments @("inspect", $id) -WorkingDirectory $Root
      Save-TextFileUtf8NoBom -Path (Join-Path $Artifacts "container_inspect.json") -Content $insp.StdOut
    }
  } catch {
    Save-TextFileUtf8NoBom -Path (Join-Path $Artifacts "diagnostics_error.txt") -Content ($_ | Out-String)
  }
}

function Compose-Up {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ComposePath
  )

  $base = ComposeArgsBase -Root $Root -ComposePath $ComposePath

  if ($Pull) {
    Write-Log "Pulling images"
    $pull = Exec -FilePath "docker" -Arguments ($base + @("pull")) -WorkingDirectory $Root
    if ($pull.ExitCode -ne 0) {
      throw "docker compose pull failed: $($pull.StdErr)"
    }
  }

  $upArgs = $base + @("up", "-d")
  if (-not $NoBuild) {
    $upArgs += @("--build")
  }

  Write-Log "Starting services: docker $($upArgs -join ' ')"
  $up = Exec -FilePath "docker" -Arguments $upArgs -WorkingDirectory $Root
  if ($up.ExitCode -ne 0) {
    throw "docker compose up failed: $($up.StdErr)"
  }
}

function Compose-Down {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ComposePath
  )
  $base = ComposeArgsBase -Root $Root -ComposePath $ComposePath
  $downArgs = $base + @("down", "--volumes", "--remove-orphans")
  Write-Log "Tearing down: docker $($downArgs -join ' ')"
  $down = Exec -FilePath "docker" -Arguments $downArgs -WorkingDirectory $Root
  if ($down.ExitCode -ne 0) {
    Write-Log "docker compose down failed: $($down.StdErr)" "WARN"
  }
}

function Run-E2E {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Cmd
  )

  Write-Log "Running E2E command: $Cmd"
  $cmdExe = "powershell"
  $cmdArgs = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", $Cmd)

  if ($PSVersionTable.PSEdition -eq "Core") {
    $cmdExe = "pwsh"
    $cmdArgs = @("-NoProfile", "-NonInteractive", "-Command", $Cmd)
  }

  $r = Exec -FilePath $cmdExe -Arguments $cmdArgs -WorkingDirectory $Root
  Save-TextFileUtf8NoBom -Path (Join-Path $ArtifactsDirResolved "e2e_stdout.txt") -Content $r.StdOut
  Save-TextFileUtf8NoBom -Path (Join-Path $ArtifactsDirResolved "e2e_stderr.txt") -Content $r.StdErr
  return $r.ExitCode
}

Assert-Command -Name "docker"

$ProjectRootResolved = (Resolve-Path -LiteralPath $ProjectRoot).Path
$ComposePathResolved = Resolve-ComposeFile -Root $ProjectRootResolved

if (-not $ArtifactsDir -or $ArtifactsDir.Trim().Length -eq 0) {
  $ArtifactsDir = Join-Path -Path $ProjectRootResolved -ChildPath "artifacts\e2e"
}
$ArtifactsDirResolved = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Path $ArtifactsDir -Force)).Path

New-Dir -Path $ArtifactsDirResolved

$runId = (Get-Date).ToString("yyyyMMdd_HHmmss")
$runDir = Join-Path -Path $ArtifactsDirResolved -ChildPath $runId
New-Dir -Path $runDir
$ArtifactsDirResolved = $runDir

Write-Log "ProjectRoot: $ProjectRootResolved"
Write-Log "ComposeFile: $ComposePathResolved"
Write-Log "Artifacts: $ArtifactsDirResolved"
Write-Log "ServiceName: $ServiceName"
Write-Log "HealthUrl: $HealthUrl"
Write-Log "StartupTimeoutSec: $StartupTimeoutSec"
Write-Log "ComposeProjectName: $ComposeProjectName"
Write-Log "ComposeProfile: $ComposeProfile"

$exitCode = 0
$upSucceeded = $false

try {
  Compose-Up -Root $ProjectRootResolved -ComposePath $ComposePathResolved
  $upSucceeded = $true

  $containerId = Get-ComposeContainerId -Root $ProjectRootResolved -ComposePath $ComposePathResolved -Svc $ServiceName
  if ($containerId) {
    Write-Log "ContainerId for '$ServiceName': $containerId"
  } else {
    Write-Log "ContainerId for '$ServiceName' not found (service may be named differently or not started)" "WARN"
  }

  $healthyHttp = $false
  if ($HealthUrl -and $HealthUrl.Trim().Length -gt 0) {
    Write-Log "Waiting for HTTP health: $HealthUrl"
    $healthyHttp = Try-HttpHealth -Url $HealthUrl -TimeoutSec $StartupTimeoutSec -IntervalSec $HealthPollIntervalSec
    if ($healthyHttp) {
      Write-Log "HTTP health OK"
    } else {
      Write-Log "HTTP health did not become ready within timeout" "WARN"
    }
  }

  $healthyContainer = $false
  if ($containerId) {
    Write-Log "Waiting for container healthcheck (if defined)"
    $healthyContainer = Try-ContainerHealth -ContainerId $containerId -TimeoutSec $StartupTimeoutSec -IntervalSec $HealthPollIntervalSec
    if ($healthyContainer) {
      Write-Log "Container healthcheck OK"
    } else {
      Write-Log "Container healthcheck not confirmed (either unhealthy, timeout, or healthcheck not defined)" "WARN"
    }
  }

  if (-not $healthyHttp -and -not $healthyContainer) {
    Write-Log "Readiness not confirmed by HTTP nor container health. Dumping diagnostics and failing." "ERROR"
    Dump-Diagnostics -Root $ProjectRootResolved -ComposePath $ComposePathResolved -Artifacts $ArtifactsDirResolved
    throw "Service readiness not confirmed"
  }

  if ($DumpLogs -eq "Always") {
    Dump-Diagnostics -Root $ProjectRootResolved -ComposePath $ComposePathResolved -Artifacts $ArtifactsDirResolved
  }

  $exitCode = Run-E2E -Root $ProjectRootResolved -Cmd $E2ECommand

  if ($exitCode -ne 0) {
    Write-Log "E2E failed with exit code $exitCode" "ERROR"
    if ($DumpLogs -eq "OnFailure") {
      Dump-Diagnostics -Root $ProjectRootResolved -ComposePath $ComposePathResolved -Artifacts $ArtifactsDirResolved
    }
  } else {
    Write-Log "E2E passed"
  }
}
catch {
  $exitCode = 1
  Save-TextFileUtf8NoBom -Path (Join-Path $ArtifactsDirResolved "exception.txt") -Content ($_ | Out-String)
  if ($upSucceeded -and ($DumpLogs -eq "OnFailure" -or $DumpLogs -eq "Always")) {
    Dump-Diagnostics -Root $ProjectRootResolved -ComposePath $ComposePathResolved -Artifacts $ArtifactsDirResolved
  }
  Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
}
finally {
  if (-not $NoDown) {
    if ($upSucceeded) {
      Compose-Down -Root $ProjectRootResolved -ComposePath $ComposePathResolved
    }
  } else {
    Write-Log "NoDown set, skipping teardown" "WARN"
  }
}

exit $exitCode
