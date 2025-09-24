# redteam_toolkit/privilege_escalation/windows/win_privesc.ps1

<# 
.DESCRIPTION
  Advanced Privilege Escalation Scanner and Exploiter for Windows
  Version: Genesis-PrivEsc-v7 (industrial grade)
#>

param(
    [switch]$Silent,
    [string]$ReportPath = "$env:Temp\priv_esc_report.json"
)

function Get-OSInfo {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
}

function Check-Admin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-UnquotedServicePaths {
    Get-WmiObject win32_service | Where-Object {
        $_.PathName -match " " -and $_.PathName -notmatch '^".*"$'
    } | Select-Object Name, StartName, PathName
}

function Check-UACBypass {
    $paths = @(
        "$env:windir\System32\fodhelper.exe",
        "$env:windir\System32\eventvwr.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            [PSCustomObject]@{
                Executable = $p
                PotentialBypass = $true
            }
        }
    }
}

function Find-AlwaysInstallElevated {
    $reg1 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $reg2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    return @{
        HKCU = $reg1.AlwaysInstallElevated
        HKLM = $reg2.AlwaysInstallElevated
    }
}

function Get-SchedTasksAsUser {
    Get-ScheduledTask | Where-Object {
        ($_.Principal.RunLevel -eq "Highest") -and ($_.Principal.UserId -ne $env:USERNAME)
    } | Select-Object TaskName, TaskPath, Principal
}

function Get-WritableServices {
    $services = Get-WmiObject win32_service
    $results = @()
    foreach ($svc in $services) {
        try {
            $acl = Get-Acl -Path $svc.PathName.Split(" ")[0]
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match $env:USERNAME -and $ace.FileSystemRights -match "Write") {
                    $results += $svc
                }
            }
        } catch {}
    }
    return $results
}

function Export-Report {
    param (
        [hashtable]$Data
    )
    $json = $Data | ConvertTo-Json -Depth 5
    $json | Out-File -Encoding UTF8 -FilePath $ReportPath
}

# MAIN
$Report = @{
    Time = (Get-Date)
    User = $env:USERNAME
    IsAdmin = Check-Admin
    OS = Get-OSInfo
    UnquotedServicePaths = Find-UnquotedServicePaths
    UACBypassMethods = Check-UACBypass
    AlwaysInstallElevated = Find-AlwaysInstallElevated
    SchedTasksAsUser = Get-SchedTasksAsUser
    WritableServices = Get-WritableServices
}

Export-Report -Data $Report

if (-not $Silent) {
    Write-Output "`n[+] Privilege Escalation Report exported to: $ReportPath"
}
