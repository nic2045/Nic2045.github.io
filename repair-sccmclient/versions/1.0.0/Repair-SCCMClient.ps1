#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Repairs a broken ConfigMgr (SCCM) client locally, standalone.
.DESCRIPTION
    Runs the selected repair steps one after another and writes a log file.
    Runs without NDTools and needs no network access.
    Steps: CcmRepair, Policy, Registration, Wmi, Cache, Validate.
.PARAMETER Step
    Steps to run. Default: all except Wmi (the WMI reset is invasive, run it on purpose only).
.PARAMETER LogPath
    Folder for the log file. Default: ProgramData\RepairSCCMClient.
.EXAMPLE
    .\Repair-SCCMClient.ps1 -WhatIf
.EXAMPLE
    .\Repair-SCCMClient.ps1 -Step Policy, Validate
.NOTES
    Author: Nico Dubiellak   (publish-scan: ignore)
    Exit codes: 0 = ok, 1 = at least one step failed, 2 = client not installed
    Inspired by the repair steps listed in https://github.com/bijudevops/SCCMagentRepair
    (own implementation, no code taken from it).

    Version: 1.0.0   (x-release-please-version)

    Changelog
      1.0.0
        - First version
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('CcmRepair', 'Policy', 'Registration', 'Wmi', 'Cache', 'Validate')]
    [string[]]$Step = @('CcmRepair', 'Policy', 'Registration', 'Cache', 'Validate'),

    [string]$LogPath = (Join-Path $env:ProgramData 'RepairSCCMClient')
)

$ErrorActionPreference = 'Stop'
$CcmDir = Join-Path $env:WinDir 'CCM'
$script:Failed = $false

if (-not (Test-Path $LogPath)) { $null = New-Item -ItemType Directory -Path $LogPath -Force }
$LogFile = Join-Path $LogPath ('repair-sccmclient.{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    if ($Step -notcontains $Name) { return }
    Write-Log "Step $Name"
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $Name)) { return }
    try { & $Action }
    catch { $script:Failed = $true; Write-Log "$Name failed: $($_.Exception.Message)" 'ERROR' }
}

function Stop-CcmExec {
    $svc = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name CcmExec -Force; $svc.WaitForStatus('Stopped', '00:01:00') }
}

function Start-CcmExec {
    $svc = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') { Start-Service -Name CcmExec }
}

if (-not ((Test-Path (Join-Path $CcmDir 'CcmExec.exe')) -or (Get-Service -Name CcmExec -ErrorAction SilentlyContinue))) {
    Write-Log 'ConfigMgr client is not installed.' 'ERROR'
    exit 2
}

Invoke-Step 'CcmRepair' {
    $exe = Join-Path $CcmDir 'CcmRepair.exe'
    if (-not (Test-Path $exe)) { Write-Log 'CcmRepair.exe not found, skipped.' 'WARN'; return }
    $p = Start-Process -FilePath $exe -ArgumentList '/q' -Wait -PassThru
    Write-Log "CcmRepair ExitCode $($p.ExitCode)"
    if ($p.ExitCode -ne 0) { throw "CcmRepair ExitCode $($p.ExitCode)" }
}

Invoke-Step 'Policy' {
    Stop-CcmExec
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\ActualConfig',
                      'HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\RequestedConfig' -Recurse -Force -ErrorAction SilentlyContinue
    Start-CcmExec
    $null = Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule `
        -Arguments @{ sScheduleID = '{00000000-0000-0000-0000-000000000021}' }   # publish-scan: ignore (fixed ConfigMgr schedule ID for Machine Policy)
    Write-Log 'Machine policy reset, retrieval triggered.'
}

Invoke-Step 'Registration' {
    $exe = Join-Path $CcmDir 'ccmsetup.exe'
    if (-not (Test-Path $exe)) { throw 'ccmsetup.exe not found.' }
    $p = Start-Process -FilePath $exe -ArgumentList 'RESETKEYINFORMATION=TRUE' -Wait -PassThru
    Write-Log "ccmsetup ExitCode $($p.ExitCode)"
    if ($p.ExitCode -ne 0) { throw "ccmsetup ExitCode $($p.ExitCode)" }
}

Invoke-Step 'Wmi' {
    $out = & winmgmt.exe /verifyrepository
    Write-Log "WMI: $out"
    if ($LASTEXITCODE -eq 0 -and $out -match 'consistent' -and $out -notmatch 'inconsistent') { return }
    Stop-CcmExec
    & winmgmt.exe /resetrepository | ForEach-Object { Write-Log "WMI: $_" }
    Start-CcmExec
}

Invoke-Step 'Cache' {
    Stop-CcmExec
    $cache = Join-Path $CcmDir 'Cache'
    if (Test-Path $cache) { Get-ChildItem -Path $cache -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
    Start-CcmExec
    Write-Log 'CCM cache cleared.'
}

Invoke-Step 'Validate' {
    $svc = Get-Service -Name CcmExec
    Write-Log "Service CcmExec: $($svc.Status)"
    if ($svc.Status -ne 'Running') { throw 'CcmExec is not running.' }
    $client = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client
    Write-Log "Client version: $($client.ClientVersion)"
    $site = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Authority -ErrorAction SilentlyContinue
    if ($site) { Write-Log "Site assignment: $($site.Name)" } else { Write-Log 'No site assignment (SMS_Authority empty).' 'WARN'; $script:Failed = $true }
}

Write-Log "Done. Log: $LogFile"
if ($script:Failed) { exit 1 }
exit 0
