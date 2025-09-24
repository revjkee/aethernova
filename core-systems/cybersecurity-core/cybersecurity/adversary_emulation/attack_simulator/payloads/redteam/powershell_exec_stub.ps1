<# 
.SYNOPSIS
  PowerShell Exec Stub (Safe Industrial Edition)

.DESCRIPTION
  Промышленный безопасный «исполнительный» заглушечный скрипт для сценариев adversary emulation.
  По умолчанию выполняет ТОЛЬКО симуляцию команд (Dry-Run) с полным журналированием,
  белым списком допустимых команд и строгими проверками. Реальное исполнение разрешается 
  только при явном флаге -LabMode и прохождении всех проверок allowlist.

  Основные свойства:
    - Dry-Run по умолчанию (безопасно)
    - Белый список (exact/regex) и блок-лист опасных примитивов
    - Подробные логи + Transcript на диск
    - Запись событий в Windows Event Log (при наличии прав)
    - Структурированный JSON-вывод результатов
    - Запрет сетевой активности по умолчанию
    - Поддержка входного JSON со списком команд
    - Хэширование ресурсов для аудита (SHA256)
    - Никаких ExecutionPolicy Bypass в запуске дочерних процессов

.PARAMETER Command
  Список команд (строк) для симуляции/выполнения.

.PARAMETER InputJsonPath
  Путь к JSON-файлу вида:
  {
    "commands": ["Get-Process", "Get-ChildItem -Path C:\\Temp"]
  }

.PARAMETER AllowlistPath
  Путь к JSON allowlist:
  {
    "exact": ["Get-Process","Get-Service"],
    "regex": ["^Get-ChildItem\\b.*$","^Test-Connection\\b.*$"]
  }

.PARAMETER LogDir
  Каталог для логов (по умолчанию: ./logs)

.PARAMETER LabMode
  Разрешить реальное исполнение команд после прохождения всех проверок.

.PARAMETER DryRun
  Насильно включить сухой прогон (симуляцию), даже в LabMode.

.PARAMETER NoNetwork
  Запретить сетевые команды/аргументы (по умолчанию включено).

.PARAMETER VerboseLog
  Включить подробный вывод.

.PARAMETER Strict
  Трактовать любые сомнения как отказ (усиленная политика отказа).

.PARAMETER EnableEventLog
  Писать события в Windows Event Log (Application/CyberSim-PowerShellExec), если возможно.

.EXAMPLE
  .\powershell_exec_stub.ps1 -InputJsonPath .\plan.json -AllowlistPath .\allow.json -LabMode

.EXAMPLE
  .\powershell_exec_stub.ps1 -Command "Get-Process","Get-ChildItem C:\Temp" -DryRun

.NOTES
  Версия: 1.0.0-safe
  Ядро предназначено для безопасной эмуляции и контроля. 
  В проде держите Dry-Run включённым по умолчанию.
#>

[CmdletBinding(PositionalBinding=$false)]
param(
  [Parameter(Mandatory=$false)]
  [string]$InputJsonPath,

  [Parameter(Mandatory=$false)]
  [string[]]$Command,

  [Parameter(Mandatory=$false)]
  [string]$AllowlistPath = ".\allowlist.json",

  [Parameter(Mandatory=$false)]
  [string]$LogDir = ".\logs",

  [Parameter(Mandatory=$false)]
  [switch]$LabMode,

  [Parameter(Mandatory=$false)]
  [switch]$DryRun,

  [Parameter(Mandatory=$false)]
  [switch]$NoNetwork = $true,

  [Parameter(Mandatory=$false)]
  [switch]$VerboseLog,

  [Parameter(Mandatory=$false)]
  [switch]$Strict,

  [Parameter(Mandatory=$false)]
  [switch]$EnableEventLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Utility: JSON Safe Load ----------
function Read-JsonFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "JSON file not found: $Path"
  }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return $raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Failed to parse JSON '$Path': $($_.Exception.Message)"
  }
}

# ---------- Utility: SHA256 ----------
function Get-FileSha256 {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop
    return $hash.Hash
  } catch {
    return $null
  }
}

# ---------- Logging setup ----------
$null = New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$sessionId   = [guid]::NewGuid().ToString()
$timeStamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$logBaseName = "ps_exec_stub-$($timeStamp)-$($sessionId)"
$logPath     = Join-Path $LogDir "$logBaseName.log"
$transcript  = Join-Path $LogDir "$logBaseName.transcript.txt"
$summaryPath = Join-Path $LogDir "$logBaseName.summary.json"

# Start transcript (best effort)
try {
  Start-Transcript -Path $transcript -Append | Out-Null
} catch { }

# ---------- Event Log setup (best effort) ----------
$eventSource = "CyberSim-PowerShellExec"
$eventLog    = "Application"
$eventReady  = $false
if ($EnableEventLog) {
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
      # Requires admin; if fails, we fallback silently
      New-EventLog -LogName $eventLog -Source $eventSource -ErrorAction Stop
    }
    $eventReady = $true
  } catch {
    $eventReady = $false
  }
}
function Write-ExecEvent {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [Parameter(Mandatory=$false)][int]$EventId = 55001,
    [Parameter(Mandatory=$false)][ValidateSet("Information","Warning","Error")] [string]$EntryType = "Information"
  )
  try {
    if ($eventReady) {
      Write-EventLog -LogName $eventLog -Source $eventSource -EntryType $EntryType -EventId $EventId -Message $Message
    }
  } catch { }
}

# ---------- Console logger ----------
function LogInfo { param([string]$m) if ($VerboseLog) { Write-Host "[INFO] $m" } Add-Content -LiteralPath $logPath -Value "[INFO] $m" }
function LogWarn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow; Add-Content -LiteralPath $logPath -Value "[WARN] $m" }
function LogErr  { param([string]$m) Write-Host "[ERR ] $m" -ForegroundColor Red;    Add-Content -LiteralPath $logPath -Value "[ERR ] $m" }

LogInfo "Session: $sessionId"
LogInfo "Timestamp: $timeStamp"
LogInfo "PWD: $(Get-Location)"

# ---------- Load commands ----------
$commands = @()
if ($InputJsonPath) {
  $j = Read-JsonFile -Path $InputJsonPath
  if ($j -and $j.commands) {
    $commands += @($j.commands | ForEach-Object { $_.ToString() })
  }
}
if ($Command) { $commands += $Command }
$commands = $commands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique

if (-not $commands -or $commands.Count -eq 0) {
  LogWarn "No commands provided; nothing to simulate/execute."
}

# ---------- Load allowlist ----------
$allowExact = @()
$allowRegex = @()
$allowSha   = $null
if (Test-Path -LiteralPath $AllowlistPath) {
  $allowSha = Get-FileSha256 -Path $AllowlistPath
  $allow = Read-JsonFile -Path $AllowlistPath
  if ($allow -and $allow.exact) { $allowExact += @($allow.exact | ForEach-Object { $_.ToString().Trim() }) }
  if ($allow -and $allow.regex) { $allowRegex += @($allow.regex | ForEach-Object { $_.ToString() }) }
  LogInfo "Allowlist loaded. exact=$($allowExact.Count), regex=$($allowRegex.Count), sha256=$allowSha"
} else {
  LogWarn "Allowlist not found: $AllowlistPath. Strict=$Strict"
  if ($Strict) {
    LogErr "Strict mode: no allowlist -> deny all."
  }
}

# ---------- Blocklist (hard-coded minimal) ----------
# Целенаправленно блокируем типичные опасные примитивы
$blockPatterns = @(
  '(?i)\bInvoke-Expression\b', '(?i)\bIEX\b',
  '(?i)\bAdd-MpPreference\b', '(?i)\bSet-MpPreference\b',
  '(?i)\bDisable[- ]\w+', '(?i)\bEnable[- ]\w+Firewall\b',
  '(?i)\bInvoke-WebRequest\b', '(?i)\bcurl\b', '(?i)\bInvoke-RestMethod\b',
  '(?i)\bbitsadmin\b', '(?i)\breg(\.exe)?\b.*\bRun\b',
  '(?i)\bschtasks(\.exe)?\b', '(?i)\brundll32(\.exe)?\b', '(?i)\bwmic(\.exe)?\b',
  '(?i)FromBase64String\(', '(?i)\bDownloadString\b'
)

# ---------- Network guard ----------
function Contains-NetworkHint {
  param([string]$cmd)
  if (-not $cmd) { return $false }
  return ($cmd -match '(?i)\b(?:https?|ftp)://') -or ($cmd -match '(?i)\b(New-Object\s+Net\.WebClient)')
}

# ---------- Allow check ----------
function Test-AllowedCommand {
  param([Parameter(Mandatory=$true)][string]$cmd)

  foreach ($bp in $blockPatterns) {
    if ($cmd -match $bp) { return $false }
  }
  if ($NoNetwork.IsPresent -and (Contains-NetworkHint -cmd $cmd)) {
    return $false
  }
  if ($allowExact -and ($allowExact -contains $cmd)) { return $true }

  if ($allowRegex) {
    foreach ($rx in $allowRegex) {
      try {
        if ([regex]::IsMatch($cmd, $rx)) { return $true }
      } catch {
        # некорректный regex в allowlist — игнорируем
        continue
      }
    }
  }

  # если Strict — запрещаем всё, что не в allowlist
  if ($Strict) { return $false }

  # по умолчанию: если нет allowlist вообще — всё запрещено
  if (-not (Test-Path -LiteralPath $AllowlistPath)) { return $false }

  # иначе deny
  return $false
}

# ---------- Executor (safe by default) ----------
function Invoke-CommandSafe {
  param(
    [Parameter(Mandatory=$true)][string]$cmd,
    [Parameter(Mandatory=$true)][switch]$lab
  )
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $result = [ordered]@{
    command     = $cmd
    allowed     = $false
    executed    = $false
    exitCode    = $null
    stdout      = $null
    stderr      = $null
    durationMs  = 0
    error       = $null
  }

  try {
    $isAllowed = Test-AllowedCommand -cmd $cmd
    $result.allowed = [bool]$isAllowed

    if (-not $isAllowed) {
      LogWarn "DENY: '$cmd'"
      return $result
    }

    if (-not $lab.IsPresent) {
      # Симуляция: ничего не запускаем
      LogInfo "SIMULATE: '$cmd'"
      return $result
    }

    if ($DryRun.IsPresent) {
      LogInfo "LAB+DRYRUN: simulate '$cmd'"
      return $result
    }

    # Реальное исполнение в LabMode: запускаем дочерний powershell без профиля/интерактива.
    $tmpOut = New-TemporaryFile
    $tmpErr = New-TemporaryFile
    try {
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = (Get-Command powershell).Source
      $psi.ArgumentList.Add("-NoProfile")
      $psi.ArgumentList.Add("-NonInteractive")
      # Без Bypass; стандартный -Command
      $psi.ArgumentList.Add("-Command")
      $psi.ArgumentList.Add($cmd)
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError  = $true
      $psi.UseShellExecute        = $false
      $psi.CreateNoWindow         = $true
      $p = New-Object System.Diagnostics.Process
      $p.StartInfo = $psi
      $null = $p.Start()
      $stdOut = $p.StandardOutput.ReadToEnd()
      $stdErr = $p.StandardError.ReadToEnd()
      $p.WaitForExit()

      $result.executed = $true
      $result.exitCode = $p.ExitCode
      $result.stdout   = $stdOut
      $result.stderr   = $stdErr

      if ($p.ExitCode -ne 0 -and $Strict) {
        LogWarn "Non-zero exit code ($($p.ExitCode)) for '$cmd' in Strict mode."
      }
    } finally {
      try { Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue } catch {}
      try { Remove-Item -LiteralPath $tmpErr -Force -ErrorAction SilentlyContinue } catch {}
    }
    return $result
  } catch {
    $result.error = $_.Exception.Message
    LogErr "EXEC ERROR: '$cmd' -> $($result.error)"
    return $result
  } finally {
    $sw.Stop()
    $result.durationMs = [int]$sw.Elapsed.TotalMilliseconds
  }
}

# ---------- Main ----------
$scriptPath   = $MyInvocation.MyCommand.Path
$scriptSha256 = Get-FileSha256 -Path $scriptPath

LogInfo "Script: $scriptPath"
LogInfo "Script SHA256: $scriptSha256"
if ($AllowlistPath) { LogInfo "Allowlist SHA256: $allowSha" }
LogInfo "LabMode=$($LabMode.IsPresent) DryRun=$($DryRun.IsPresent) NoNetwork=$($NoNetwork.IsPresent) Strict=$($Strict.IsPresent)"

$results = New-Object System.Collections.Generic.List[Object]

foreach ($c in $commands) {
  $r = Invoke-CommandSafe -cmd $c -lab:$LabMode
  $results.Add([pscustomobject]$r)
}

# ---------- Summary ----------
$summary = [ordered]@{
  sessionId     = $sessionId
  timestamp     = $timeStamp
  script        = $scriptPath
  scriptSha256  = $scriptSha256
  allowlistPath = (Resolve-Path -LiteralPath $AllowlistPath -ErrorAction SilentlyContinue).Path
  allowlistSha  = $allowSha
  logPath       = (Resolve-Path -LiteralPath $logPath -ErrorAction SilentlyContinue).Path
  transcript    = (Resolve-Path -LiteralPath $transcript -ErrorAction SilentlyContinue).Path
  labMode       = $LabMode.IsPresent
  dryRun        = $DryRun.IsPresent -or (-not $LabMode.IsPresent)
  noNetwork     = $NoNetwork.IsPresent
  strict        = $Strict.IsPresent
  eventLog      = $EnableEventLog.IsPresent
  results       = $results
}

# Пишем summary
try {
  ($summary | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $summaryPath -Encoding UTF8 -Force
  LogInfo "Summary JSON: $summaryPath"
} catch {
  LogErr "Failed to write summary: $($_.Exception.Message)"
}

# Запись события
try {
  $countTotal   = $commands.Count
  $countAllowed = ($results | Where-Object { $_.allowed }).Count
  $countExec    = ($results | Where-Object { $_.executed }).Count
  Write-ExecEvent -Message "ExecStub session=$sessionId total=$countTotal allowed=$countAllowed executed=$countExec labMode=$($LabMode.IsPresent) dryRun=$($DryRun.IsPresent -or (-not $LabMode.IsPresent)))" -EventId 55002 -EntryType Information
} catch { }

# Завершение транскрипта
try { Stop-Transcript | Out-Null } catch { }

# Итоговый вывод в STDOUT (структурированный JSON)
$summary | ConvertTo-Json -Depth 6
