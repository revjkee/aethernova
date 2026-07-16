# File: csmarket/scripts/seed.ps1
#requires -Version 7.0
Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','WARN','ERROR','FATAL')]
        [string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data
    )

    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK')

    $payload = [ordered]@{
        ts      = $ts
        level   = $Level
        msg     = $Message
        pid     = $PID
    }

    if ($null -ne $Data -and $Data.Count -gt 0) {
        foreach ($k in $Data.Keys) { $payload[$k] = $Data[$k] }
    }

    $line = ($payload | ConvertTo-Json -Compress -Depth 10)
    Write-Host $line
}

function Fail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [int]$ExitCode = 1,
        [hashtable]$Data
    )
    Write-Log -Level 'ERROR' -Message $Message -Data $Data
    exit $ExitCode
}

function Assert-Command {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$ExitCode = 10
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Fail -Message "Required command not found: $Name" -ExitCode $ExitCode -Data @{ command = $Name }
    }
}

function Resolve-RepoRoot {
    [CmdletBinding()]
    param()
    $here = $PSScriptRoot
    $root = (Resolve-Path (Join-Path $here '..')).Path
    return $root
}

function Read-DotEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @{}
    }

    $map = @{}
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop

    foreach ($raw in $lines) {
        $line = $raw.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('#')) { continue }

        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { continue }

        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()

        if ($val.StartsWith('"') -and $val.EndsWith('"') -and $val.Length -ge 2) {
            $val = $val.Substring(1, $val.Length - 2)
        } elseif ($val.StartsWith("'") -and $val.EndsWith("'") -and $val.Length -ge 2) {
            $val = $val.Substring(1, $val.Length - 2)
        }

        if ($key.Length -eq 0) { continue }
        $map[$key] = $val
    }

    return $map
}

function Set-ProcessEnvFromMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [string[]]$Allowlist,
        [switch]$Overwrite
    )

    foreach ($k in $Map.Keys) {
        if ($null -ne $Allowlist -and $Allowlist.Count -gt 0) {
            if ($Allowlist -notcontains $k) { continue }
        }

        $current = [Environment]::GetEnvironmentVariable($k, 'Process')
        if ($null -ne $current -and $current.Length -gt 0 -and -not $Overwrite) {
            continue
        }

        [Environment]::SetEnvironmentVariable($k, [string]$Map[$k], 'Process')
    }
}

function Start-SafeTranscript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$Prefix = 'seed'
    )

    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $path = Join-Path $Directory "$Prefix`_$stamp`_$PID.log"

    try {
        Start-Transcript -Path $path -Append -ErrorAction Stop | Out-Null
        return $path
    } catch {
        Write-Log -Level 'WARN' -Message 'Failed to start transcript; continuing without it.' -Data @{ error = $_.Exception.Message }
        return $null
    }
}

function Stop-SafeTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript | Out-Null } catch { }
}

function Exec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$Arguments,
        [switch]$DryRun
    )

    $cmd = $FilePath + ' ' + (($Arguments | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } }) -join ' ')
    Write-Log -Level 'INFO' -Message 'Executing' -Data @{ cmd = $cmd; dry_run = [bool]$DryRun }

    if ($DryRun) { return 0 }

    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
    $code = $p.ExitCode
    if ($code -ne 0) {
        Fail -Message 'Command failed' -ExitCode $code -Data @{ cmd = $cmd; exit_code = $code }
    }
    return $code
}

function Get-DockerComposeServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkingDirectory
    )
    Assert-Command -Name 'docker' -ExitCode 10

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'docker'
    $psi.ArgumentList.Add('compose')
    $psi.ArgumentList.Add('config')
    $psi.ArgumentList.Add('--services')
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($p.ExitCode -ne 0) {
        Fail -Message 'docker compose config failed' -ExitCode 11 -Data @{ stderr = $stderr.Trim() }
    }

    $list = $stdout -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
    return $list
}

[CmdletBinding()]
param(
    [ValidateSet('auto','docker','local')]
    [string]$Mode = 'auto',

    [string]$EnvFile = '.env',

    [switch]$OverwriteEnv,

    [string[]]$EnvAllowlist = @(),

    [string]$ComposeFile = 'docker-compose.yml',

    [string]$ComposeService = 'api',

    [ValidateSet('run','exec')]
    [string]$ComposeStrategy = 'run',

    [string]$WorkDir,

    [string]$SeedCommand = 'python -m app.scripts.seed',

    [switch]$MigrateBeforeSeed,

    [string]$MigrateCommand = 'python -m alembic upgrade head',

    [switch]$DryRun,

    [switch]$NoTranscript,

    [int]$TimeoutSeconds = 0
)

$repoRoot = if ($WorkDir -and $WorkDir.Trim().Length -gt 0) { (Resolve-Path $WorkDir).Path } else { (Resolve-RepoRoot) }
Push-Location $repoRoot

$transcriptPath = $null
try {
    if (-not $NoTranscript) {
        $transcriptPath = Start-SafeTranscript -Directory (Join-Path $repoRoot 'logs') -Prefix 'seed'
    }

    Write-Log -Level 'INFO' -Message 'Seed start' -Data @{
        repo_root = $repoRoot
        mode = $Mode
        env_file = $EnvFile
        compose_file = $ComposeFile
        compose_service = $ComposeService
        compose_strategy = $ComposeStrategy
        dry_run = [bool]$DryRun
        migrate_before_seed = [bool]$MigrateBeforeSeed
    }

    $envPath = Join-Path $repoRoot $EnvFile
    $envMap = Read-DotEnv -Path $envPath
    if ($envMap.Count -gt 0) {
        Set-ProcessEnvFromMap -Map $envMap -Allowlist $EnvAllowlist -Overwrite:$OverwriteEnv
        Write-Log -Level 'INFO' -Message 'Loaded env file into process environment' -Data @{
            path = $envPath
            keys_loaded = $envMap.Keys.Count
            allowlist = ($EnvAllowlist -join ',')
            overwrite = [bool]$OverwriteEnv
        }
    } else {
        Write-Log -Level 'WARN' -Message 'Env file not found or empty; continuing' -Data @{ path = $envPath }
    }

    $composePath = Join-Path $repoRoot $ComposeFile
    $useDocker = $false

    if ($Mode -eq 'docker') { $useDocker = $true }
    elseif ($Mode -eq 'local') { $useDocker = $false }
    else {
        $useDocker = (Test-Path -LiteralPath $composePath)
    }

    if ($useDocker) {
        Assert-Command -Name 'docker' -ExitCode 10
        if (-not (Test-Path -LiteralPath $composePath)) {
            Fail -Message 'docker mode requested, but compose file not found' -ExitCode 12 -Data @{ compose_path = $composePath }
        }

        $services = Get-DockerComposeServices -WorkingDirectory $repoRoot
        if ($services -notcontains $ComposeService) {
            Fail -Message 'Compose service not found in docker compose config' -ExitCode 13 -Data @{
                requested_service = $ComposeService
                available_services = ($services -join ',')
            }
        }

        $seedParts = @('sh','-lc', $SeedCommand)
        $migrateParts = @('sh','-lc', $MigrateCommand)

        if ($MigrateBeforeSeed) {
            if ($ComposeStrategy -eq 'run') {
                Exec -FilePath 'docker' -Arguments @('compose','-f',$ComposeFile,'run','--rm', $ComposeService) + $migrateParts -DryRun:$DryRun | Out-Null
            } else {
                Exec -FilePath 'docker' -Arguments @('compose','-f',$ComposeFile,'exec','-T', $ComposeService) + $migrateParts -DryRun:$DryRun | Out-Null
            }
            Write-Log -Level 'INFO' -Message 'Migration completed' -Data @{ command = $MigrateCommand }
        }

        if ($ComposeStrategy -eq 'run') {
            Exec -FilePath 'docker' -Arguments @('compose','-f',$ComposeFile,'run','--rm', $ComposeService) + $seedParts -DryRun:$DryRun | Out-Null
        } else {
            Exec -FilePath 'docker' -Arguments @('compose','-f',$ComposeFile,'exec','-T', $ComposeService) + $seedParts -DryRun:$DryRun | Out-Null
        }

        Write-Log -Level 'INFO' -Message 'Seed completed (docker)' -Data @{ service = $ComposeService; command = $SeedCommand }
        exit 0
    }

    Assert-Command -Name 'python' -ExitCode 20

    $localMigrate = $MigrateCommand
    $localSeed = $SeedCommand

    if ($MigrateBeforeSeed) {
        $args = @('-c', $localMigrate)
        Exec -FilePath 'powershell' -Arguments $args -DryRun:$DryRun | Out-Null
        Write-Log -Level 'INFO' -Message 'Migration completed' -Data @{ command = $localMigrate }
    }

    $args2 = @('-c', $localSeed)
    if ($TimeoutSeconds -gt 0 -and -not $DryRun) {
        Write-Log -Level 'INFO' -Message 'Executing with timeout' -Data @{ timeout_seconds = $TimeoutSeconds }
        $job = Start-Job -ScriptBlock { param($cmd) powershell -NoProfile -NonInteractive -Command $cmd } -ArgumentList $localSeed
        $done = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $done) {
            Stop-Job -Job $job -Force | Out-Null
            Remove-Job -Job $job -Force | Out-Null
            Fail -Message 'Seed timed out' -ExitCode 30 -Data @{ timeout_seconds = $TimeoutSeconds }
        }
        $out = Receive-Job -Job $job -Keep
        Remove-Job -Job $job -Force | Out-Null
        Write-Host $out
    } else {
        Exec -FilePath 'powershell' -Arguments $args2 -DryRun:$DryRun | Out-Null
    }

    Write-Log -Level 'INFO' -Message 'Seed completed (local)' -Data @{ command = $localSeed }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    $stack = $_.ScriptStackTrace
    Write-Log -Level 'FATAL' -Message 'Unhandled error' -Data @{ error = $msg; stack = $stack }
    exit 99
}
finally {
    try { Pop-Location } catch { }
    Stop-SafeTranscript
    if ($transcriptPath) {
        Write-Log -Level 'INFO' -Message 'Transcript saved' -Data @{ path = $transcriptPath }
    }
}
