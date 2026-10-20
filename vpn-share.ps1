<#
.SYNOPSIS
  Shares the Barracuda VPN of this client (Client 1) over an Ethernet cable with a second client (Client 2).

.DESCRIPTION
  Client 1 has internet over WLAN and connects the Barracuda VPN. The script shares that VPN
  through Windows Internet Connection Sharing (ICS): VPN adapter = source, cable adapter = target
  (192.168.137.1). Client 2 needs no admin rights and no VPN software; it gets a DHCP address.

      Internet --WLAN--> [ Client 1 + VPN ] --cable--> [ Client 2 ]

  Flow (Step Auto): prerequisite panel, then 6 phases: policies, WLAN, cable, VPN, ICS, summary.
  Each phase waits for its condition; on timeout it asks [R]etry / [S]kip (soft checks only) / [A]bort.
  Cyan "->" lines tell the admin what to do (colors: default = info, dark green = done, cyan = to-do, yellow = warning, red = error). Everything is logged to vpn-share.log.

.PARAMETER Step
  Auto = full flow (default); Prep = policies only; Share = ICS only; Off = tear down.

.PARAMETER VpnProfileName
  Barracuda profile to connect. Empty = the profile whose description contains VpnProfilePattern is used.

.PARAMETER VpnProfilePattern
  Text searched in the profile description when no VpnProfileName is given (default '_Standard'). If several match, the first is used (warning).

.PARAMETER VpnTestHost
  Internal host that must be reachable through the VPN (DNS lookup, plus a TCP test if VpnTestPort is set). Define it in vpn-share.config.json. Empty = a domain controller of the client's own domain is looked up via DNS SRV (fallback: %LOGONSERVER%); not domain-joined = test skipped.

.PARAMETER VpnTestPort
  Optional TCP port on VpnTestHost (e.g. 389) for a real reachability test through the tunnel. Default 389 when the domain controller was auto-detected.

.PARAMETER VpnPattern
  Text in the description of the VPN adapter.

.PARAMETER InternetTestHost
  Internet test host (port 80).

.PARAMETER VpnAdapter
  Override VPN adapter detection (name as in Get-NetAdapter).

.PARAMETER LanAdapter
  Override cable adapter detection (name as in Get-NetAdapter).

.PARAMETER KeepVpn
  With -Step Off: keep the VPN connected.

.PARAMETER DryRun
  Check everything once and report with [DRYRUN]; changes nothing (log: vpn-share-dryrun.log).

.PARAMETER Demo
  Walk through the complete operator flow (panel, hints, prompts, countdown, summary) with SIMULATED
  checks. Changes nothing and needs no admin rights. Log: vpn-share-demo.log.

.PARAMETER DemoFail
  With -Demo: every gate fails once so the Retry/Skip/Abort prompts are shown too.

.PARAMETER DebugInfo
  Show [DEBUG] lines (current state, adapters, profile IDs). Off by default.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\vpn-share\vpn-share.ps1 -VpnProfileName "MyProfile"

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\vpn-share\vpn-share.ps1 -Step Off

.EXAMPLE
  # Run from the Gist without a file (the Gist copy has no BOM; pin the raw URL to a revision if needed)
  & ([scriptblock]::Create((irm "<raw-url>"))) -VpnProfileName "MyProfile"

.NOTES
  Config file: copy vpn-share.config.json.example to vpn-share.config.json (git-ignored) next to the
  script or in C:\Tools\vpn-share and adjust the values.
  Command line wins over the file. Do not use "iex (iwr ...)": parameters are impossible there.

  Changes (all reverted by -Step Off; originals are backed up to C:\*-policy-backup.reg):
    1. Policies: NC_ShowSharedAccessUI removed (GPO blocks ICS), fBlockNonDomain = 0 (GPO drops WLAN with VPN)
    2. Service WlanSvc restarted once, SharedAccess set to Manual and started
    3. ICS enabled VPN -> cable. Hyper-V/WSL adapters (vEthernet*) are never touched.

  Safety: the cable goes DIRECTLY from Client 1 to Client 2, never into a wall socket or switch
  (ICS runs a DHCP server). Cable adapters with a default route are refused.
  Client 1 must stay on and connected; after a VPN reconnect run the script again.
  BIOS (once): disable "Wireless Radio Control" -> "Control WLAN radio", or the WLAN drops when the cable is plugged in.
  When started from memory, log and state file are written to %TEMP%.

  Version: v1.0.0 (build 261020.2229)

  Changelog
    1.0.0 (2026-10-20)
      - Prerequisite panel (admin, adapters enabled, Barracuda profile, WLAN internet, cable) before anything changes
      - Automatic VPN disconnect with 3-2-1 countdown; VPN verified via Barracuda status and an optional test target
      - Retry/Skip/Abort prompts with long timeouts; Enter-driven choice blocks for every operator input
      - DHCP check for Client 2, summary panel, teardown offer at the end or after an abort (state file)
      - -Demo / -DemoFail simulate the whole flow; -DryRun checks the real system without changes; -DebugInfo for details
      - Config file for internal values (profile, test target); runnable from a Gist/scriptblock
      - Console colors: default = info, dark green = done, cyan = to-do, yellow = warning, red = error
#>
[CmdletBinding()]
param(
  [ValidateSet('Auto', 'Prep', 'Share', 'Off')][string]$Step = 'Auto',
  [string]$VpnAdapter,
  [string]$LanAdapter,
  [string]$VpnPattern = 'Barracuda Virtual Adapter',
  [string]$VpnProfileName,
  [string]$VpnProfilePattern = '_Standard',
  [string]$VpnTestHost,
  [int]$VpnTestPort,
  [string]$InternetTestHost = 'www.msftconnecttest.com',
  [switch]$KeepVpn,
  [switch]$DryRun,
  [switch]$Demo,
  [switch]$DemoFail,
  [switch]$DebugInfo
)

$ErrorActionPreference = 'Stop'   # any error aborts and lands in the catch at the bottom
if ($DemoFail) { $Demo = [switch]$true }   # -DemoFail alone must never run for real

#region Windows PowerShell 5.1 relaunch
# The Barracuda module is built for .NET Framework and does not load in PowerShell 7.
if ($PSVersionTable.PSEdition -eq 'Core') {
  $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $self = $PSCommandPath
  if (-not $self) {   # started from memory (Gist/scriptblock): write the script to a file first
    $self = Join-Path $env:TEMP 'vpn-share.ps1'
    Set-Content -Path $self -Value $MyInvocation.MyCommand.ScriptBlock.ToString() -Encoding UTF8
  }
  $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $self)
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    if ($value -is [switch]) { if ($value.IsPresent) { $relaunch += "-$key" } }
    else { $relaunch += "-$key"; $relaunch += [string]$value }
  }
  & $exe @relaunch
  if ($PSCommandPath) { exit $LASTEXITCODE } else { return }   # exit would close the calling console
}
#endregion

#region Configuration
$cfgFile = $null
foreach ($dir in @($PSScriptRoot, 'C:\Tools\vpn-share')) {
  if ($dir -and -not $cfgFile -and (Test-Path (Join-Path $dir 'vpn-share.config.json'))) {
    $cfgFile = Join-Path $dir 'vpn-share.config.json'
  }
}
if ($cfgFile) {
  $cfg = Get-Content -Path $cfgFile -Raw | ConvertFrom-Json
  foreach ($name in 'VpnProfileName', 'VpnProfilePattern', 'VpnTestHost', 'VpnTestPort', 'VpnPattern', 'InternetTestHost') {
    if (-not $PSBoundParameters.ContainsKey($name) -and $cfg.$name) { Set-Variable -Name $name -Value ([string]$cfg.$name) }
  }
}

$ncKey     = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'   # GPO: ICS lock
$wcmKey    = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'    # GPO: WLAN disconnect
$LogDir    = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
$LogFile   = Join-Path $LogDir $(if ($Demo) { 'vpn-share-demo.log' } elseif ($DryRun) { 'vpn-share-dryrun.log' } else { 'vpn-share.log' })
$script:DemoSeen = @{}   # demo only: gates that already failed once (-DemoFail)
$script:DemoPanelRuns = 0
$StateFile = Join-Path $LogDir 'vpn-share.state'   # exists while changes are active and not reverted
$script:Sum               = @{}      # results for the final summary
$script:Ssid              = $null    # WLAN to reconnect if it gets dropped
$script:VpnConnectPlanned = $false   # dry run only: Connect-VPN would have run
$script:InetIdx           = $null    # WLAN adapter index, remembered after phase 2
#endregion

#region Logging and console output
function Write-Ui {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
  param([string]$Text, [string]$Color, [switch]$NoNewline, [string]$Background)
  if ($Background) { Write-Host $Text -ForegroundColor $Color -BackgroundColor $Background -NoNewline:$NoNewline }
  elseif ($Color) { Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline }
  else { Write-Host $Text -NoNewline:$NoNewline }
}

# Choice prompt used for every operator input: blank line, colored question bar, key line, then the input.
function Read-Choice {
  param([string]$Question, [string]$Keys, [ValidateSet('Todo', 'Error')][string]$Kind = 'Todo')
  $bar = if ($Kind -eq 'Todo') { 'DarkCyan' } else { 'DarkRed' }
  Write-Ui ''
  Write-Ui (' ' + [char]0x25B6 + ' ' + $Question).PadRight(76) 'White' -Background $bar
  Write-Ui "   -> $Keys" 'Cyan'
  Read-Host '  Auswahl'
}
function Write-Log {
  param([string]$Message, [string]$Color)
  $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
  Write-Ui $line $Color
  try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { $null = $_ }
}

function Write-DebugLog {
  param([string]$Message)
  if ($DebugInfo) { Write-Log "[DEBUG] $Message" }
}

function Write-PanelBorder {
  param([ValidateSet('top', 'mid', 'bottom')][string]$Kind, [string]$Title = '')
  $h = [string][char]0x2500
  $left = [string][char]$(switch ($Kind) { 'top' { 0x250C } 'mid' { 0x251C } default { 0x2514 } })
  $right = [string][char]$(switch ($Kind) { 'top' { 0x2510 } 'mid' { 0x2524 } default { 0x2518 } })
  $inner = if ($Title) { "$h $Title " } else { '' }
  Write-Ui ($left + $inner + ($h * (74 - $inner.Length)) + $right) 'Gray'
}

function Write-PanelLine {
  param([string]$Text, [string]$Color = 'Gray')
  $v = [string][char]0x2502
  $lines = @()
  while ($Text.Length -gt 72) {   # wrap at the last space, continuation lines are indented
    $cut = $Text.LastIndexOf(' ', 72)
    if ($cut -lt 20) { $cut = 72 }
    $lines += $Text.Substring(0, $cut).TrimEnd()
    $Text = '    ' + $Text.Substring($cut).TrimStart()
  }
  $lines += $Text
  foreach ($line in $lines) {
    Write-Ui "$v " 'Gray' -NoNewline
    Write-Ui $line.PadRight(72) $Color -NoNewline
    Write-Ui " $v" 'Gray'
  }
}
#endregion

#region General helpers
function Test-Admin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# The state file marks "system was changed and not reverted yet".
function Save-RunState {
  param([string]$What)
  if ($DryRun -or $Demo) { return }
  try { Add-Content -Path $StateFile -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $What) -Encoding UTF8 } catch { $null = $_ }
}

function Remove-RunState {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
  param()
  if (-not ($DryRun -or $Demo)) { Remove-Item -Path $StateFile -Force -ErrorAction SilentlyContinue }
}

function Get-RegistryValue {
  param([string]$Path, [string]$Name)
  try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Test-TcpPort {
  param([string]$HostName, [int]$Port, [int]$TimeoutMs = 3000)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $async = $client.BeginConnect($HostName, $Port, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
    $client.EndConnect($async)
    return $true
  }
  catch { return $false }
  finally { $client.Close() }
}

# Domain controller of the client's own domain, so no host has to be configured. Empty = not domain-joined / not resolvable.
function Find-DomainController {
  $domain = $env:USERDNSDOMAIN
  if ($domain) {
    try {
      $srv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$domain" -Type SRV -ErrorAction Stop |
        Where-Object { $_.Type -eq 'SRV' } | Sort-Object Priority, @{ Expression = 'Weight'; Descending = $true } | Select-Object -First 1
      if ($srv) { return [string]$srv.NameTarget }
    }
    catch { Write-Verbose "SRV-Lookup für $domain fehlgeschlagen: $($_.Exception.Message)" }
  }
  if ($env:LOGONSERVER) { return ($env:LOGONSERVER -replace '^\\\\', '') }
  ''
}

function Get-CurrentSsid {
  $line = netsh wlan show interfaces | Select-String -Pattern '^\s*SSID\s*:\s*(.+?)\s*$'
  if ($line) { $line.Matches[0].Groups[1].Value }
}

# Runs a block; in a dry run an error is only reported instead of aborting.
function Invoke-Safe {
  param([scriptblock]$Block)
  if (-not $DryRun) { & $Block; return }
  try { & $Block } catch { Write-Log "[DRYRUN] PROBLEM (real run aborts): $($_.Exception.Message)" }
}

# Gate = check with waiting and a retry prompt.
#   Check returns '' when OK, otherwise the problem text. Polls every 2 s until OK or timeout, then asks R/S/A.
#   -AfterChange: only satisfiable after a change made by the script (matters for the dry run).
function Invoke-Gate {
  param([string]$Title, [scriptblock]$Check, [string]$Hint, [int]$TimeoutSec = 120, [switch]$AllowSkip, [switch]$AfterChange)
  if ($Demo) {   # simulated: show the hint, optionally fail once (-DemoFail), then succeed
    if ($Hint) { Write-Ui "  -> $Hint" 'Cyan' }
    if ($DemoFail -and -not $script:DemoSeen[$Title]) {
      $script:DemoSeen[$Title] = $true
      Write-Log "FEHLT: $Title -> simulierter Fehler (Demo)" 'Red'
      $keys = if ($AllowSkip) { '[Enter]/[R] Wiederholen     [S] Überspringen     [A] Abbruch' } else { '[Enter]/[R] Wiederholen     [A] Abbruch' }
      $answer = Read-Choice 'Bedingung nicht erfüllt - wie weiter?' $keys 'Error'
      if ($answer -match '^[aA]') { throw "Abbruch bei: $Title" }
      if ($AllowSkip -and $answer -match '^[sS]') { Write-Log "ÜBERSPRUNGEN: $Title"; return }
    }
    Start-Sleep -Seconds 1
    Write-Log "[OK] Erledigt: $Title" 'DarkGreen'
    return
  }
  if ($DryRun) {
    if ($Hint) { Write-Log "[DRYRUN] Hinweis an den Admin im echten Lauf: $Hint" }
    $problem = [string](& $Check)
    if (-not $problem) { Write-Log "[DRYRUN] OK: $Title" }
    elseif ($AfterChange) { Write-Log "[DRYRUN] erst nach der Änderung erfüllbar: $Title (jetzt: $problem)" }
    else { Write-Log "[DRYRUN] JETZT NICHT ERFÜLLT: $Title -> $problem (echter Lauf: bis $TimeoutSec s warten, dann Rückfrage)" }
    return
  }
  if ($Hint) { Write-Ui "  -> $Hint" 'Cyan' }
  while ($true) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
      $problem = [string](& $Check)
      if (-not $problem) { Write-Log "[OK] Erledigt: $Title" 'DarkGreen'; return }
      Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    Write-Log "FEHLT: $Title -> $problem" 'Red'
    $keys = if ($AllowSkip) { '[Enter]/[R] Wiederholen     [S] Überspringen     [A] Abbruch' } else { '[Enter]/[R] Wiederholen     [A] Abbruch' }
    $answer = Read-Choice 'Bedingung nicht erfüllt - wie weiter?' $keys 'Error'
    if ($answer -match '^[aA]') { throw "Abbruch bei: $Title" }
    if ($AllowSkip -and $answer -match '^[sS]') { Write-Log "ÜBERSPRUNGEN: $Title"; return }
    if ($Hint) { Write-Ui "  -> $Hint" 'Cyan' }
  }
}
#endregion

#region Policies
# The company GPO blocks ICS and drops the WLAN once a domain network (VPN) appears.
# Originals are backed up ONCE (an existing backup is kept) and both locks are lifted temporarily.
function Backup-RegistryKey {
  param([string]$RegPath, [string]$File)
  if (Test-Path $File) { if ($DryRun) { Write-Log "[DRYRUN] Backup existiert schon: $File" }; return }
  if ($DryRun) { Write-Log "[DRYRUN] würde Backup anlegen: $File"; return }
  reg export $RegPath $File /y | Out-Null
}

function Show-PolicyPlan {
  $nc = Get-RegistryValue $ncKey 'NC_ShowSharedAccessUI'
  $wcm = Get-RegistryValue $wcmKey 'fBlockNonDomain'
  $ncText = if ($null -eq $nc) { 'nicht gesetzt (nichts zu tun)' } else { "$nc -> würde entfernt" }
  $wcmText = if ($null -eq $wcm) { 'nicht gesetzt -> würde auf 0 gesetzt' } elseif ($wcm -eq 0) { '0 (nichts zu tun)' } else { "$wcm -> würde auf 0 gesetzt" }
  Write-Log "[DRYRUN] NC_ShowSharedAccessUI: aktuell $ncText"
  Write-Log "[DRYRUN] fBlockNonDomain: aktuell $wcmText"
}

function Disable-PolicyLock {
  if ($DryRun) { Show-PolicyPlan; return }
  Remove-ItemProperty -Path $ncKey -Name NC_ShowSharedAccessUI -ErrorAction SilentlyContinue
  if (-not (Test-Path $wcmKey)) { New-Item -Path $wcmKey -Force | Out-Null }
  Set-ItemProperty -Path $wcmKey -Name fBlockNonDomain -Value 0 -Type DWord
}

function Invoke-Prep {
  if ($Demo) { Write-Log '[DEMO] würde Policies ändern (Backup, NC_ShowSharedAccessUI, fBlockNonDomain) und WlanSvc neu starten'; return }
  Backup-RegistryKey 'HKLM\Software\Policies\Microsoft\Windows\Network Connections' 'C:\nc-policy-backup.reg'
  Backup-RegistryKey 'HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'C:\wcm-policy-backup.reg'
  Disable-PolicyLock
  if ($DryRun) { Write-Log '[DRYRUN] würde Dienst WlanSvc neu starten (WLAN stockt dann kurz)'; return }
  Save-RunState 'Policies geändert'
  Restart-Service WlanSvc -Force   # so the changed policy applies; WLAN stalls briefly
  Write-Log 'Policies angepasst, WLAN-Dienst neu gestartet'
}
#endregion

#region Adapter detection
function Get-DefaultRoute {
  Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue
}

# Internet adapter = physical adapter that is Up, has a default route and the lowest metric.
# WLAN is preferred (penalty for wired), so a cable plugged into the site network is not mistaken for it.
function Find-InternetAdapter {
  $routes = Get-DefaultRoute
  $candidates = foreach ($adapter in (Get-NetAdapter -Physical | Where-Object {
        $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch $VpnPattern })) {
    $route = $routes | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Sort-Object RouteMetric | Select-Object -First 1
    if ($route) {
      $ifMetric = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).InterfaceMetric
      $penalty = if ($adapter.PhysicalMediaType -match '802\.11') { 0 } else { 10000 }
      [pscustomobject]@{ Name = $adapter.Name; ifIndex = $adapter.ifIndex; Metric = $route.RouteMetric + $ifMetric + $penalty }
    }
  }
  $candidates | Where-Object { $_ } | Sort-Object Metric | Select-Object -First 1
}

function Find-VpnAdapter {
  Get-NetAdapter | Where-Object { $_.InterfaceDescription -match $VpnPattern -and $_.Status -eq 'Up' } | Select-Object -First 1
}

# After phase 2 this is the remembered WLAN adapter, so a cable in the site network is not mistaken for it.
function Get-InetIndex {
  if ($null -ne $script:InetIdx) { return $script:InetIdx }
  $adapter = Find-InternetAdapter
  if ($adapter) { $adapter.ifIndex } else { -1 }
}

function Test-InetUp {
  if ($null -eq $script:InetIdx) { return [bool](Find-InternetAdapter) }
  $adapter = Get-NetAdapter -Physical | Where-Object { $_.ifIndex -eq $script:InetIdx -and $_.Status -eq 'Up' }
  [bool]($adapter -and (Get-DefaultRoute | Where-Object { $_.InterfaceIndex -eq $script:InetIdx }))
}

# Cable adapter to Client 2: wired, link Up, NO default route, not the internet adapter.
# Returns the adapter or a problem text for the admin.
function Get-LanState {
  param([int]$InetIndex)
  if ($LanAdapter) {
    $adapter = Get-NetAdapter -Name $LanAdapter -ErrorAction SilentlyContinue
    if (-not $adapter) { return [pscustomobject]@{ Adapter = $null; Problem = "Adapter '$LanAdapter' existiert nicht" } }
    if ($adapter.Status -ne 'Up') { return [pscustomobject]@{ Adapter = $null; Problem = "Adapter '$LanAdapter' ohne Link (Kabel gesteckt, Client 2 an?)" } }
    return [pscustomobject]@{ Adapter = $adapter; Problem = $null }
  }
  $routes = Get-DefaultRoute
  $wired = @(Get-NetAdapter -Physical | Where-Object {
      $_.Status -eq 'Up' -and $_.ifIndex -ne $InetIndex -and $_.PhysicalMediaType -notmatch '802\.11|Bluetooth' -and $_.InterfaceDescription -notmatch $VpnPattern })
  $withRoute = @($wired | Where-Object { $a = $_; $routes | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } })
  $lan = @($wired | Where-Object { $a = $_; -not ($routes | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }) })

  if ($lan.Count -eq 1) { return [pscustomobject]@{ Adapter = $lan[0]; Problem = $null } }
  if ($lan.Count -gt 1) { return [pscustomobject]@{ Adapter = $null; Problem = "Mehrere Kabel-Adapter Up ($(($lan.Name) -join ', ')) -> -LanAdapter angeben" } }
  if ($withRoute.Count -gt 0) {
    return [pscustomobject]@{ Adapter = $null; Problem = "Kabel-Adapter '$($withRoute[0].Name)' hängt in einem Netz mit Internetzugang (Standort-Netz?). Kabel muss direkt zu Client 2" }
  }
  [pscustomobject]@{ Adapter = $null; Problem = 'Kein Link am Ethernet-Adapter: Kabel gesteckt, Client 2 eingeschaltet?' }
}

# Profiles to use: the named one, else the one(s) whose description contains VpnProfilePattern (default '_Standard').
function Find-VpnProfile {
  if ($VpnProfileName) { return @(Get-BarracudaProfile $VpnProfileName) }
  @(Get-BarracudaProfile | Where-Object { $_.Description -like "*$VpnProfilePattern*" })
}

function Get-VpnProfileLabel {
  if ($VpnProfileName) { "'$VpnProfileName'" } else { "mit '$VpnProfilePattern'" }
}

# Plugging the cable or connecting the VPN can drop the WLAN; reconnect it.
function Restore-Wlan {
  if ($Demo) { return }
  if (-not (Test-InetUp) -and $script:Ssid) {
    if ($DryRun) { Write-Log "[DRYRUN] WLAN wäre weg: würde neu verbinden mit '$($script:Ssid)'"; return }
    Write-Log "WLAN weg, verbinde neu mit '$($script:Ssid)'"
    netsh wlan connect "name=$($script:Ssid)" | Out-Null
  }
}
#endregion

#region Barracuda VPN
function Import-BarracudaModule {
  if (Get-Command Connect-VPN -ErrorAction SilentlyContinue) { return }
  $manifest = Join-Path $env:ProgramFiles 'Barracuda\Network Access Client\Modules\BarracudaNetworkAccessClient\BarracudaNetworkAccessClient.psd1'
  if (-not (Test-Path $manifest)) { throw "Barracuda-Modul nicht gefunden: $manifest" }
  try { Import-Module $manifest -Force -ErrorAction Stop }
  catch { throw "Barracuda-Modul lässt sich nicht laden: $($_.Exception.Message)" }
}

# Get-VPNProfile returns a List[VPNProfile]; ForEach-Object { $_ } unrolls it so .ID/.Description/.Context are readable.
function Get-BarracudaProfile {
  param([string]$Description)
  Import-BarracudaModule
  $all = Get-VPNProfile -All -ErrorAction Stop | ForEach-Object { $_ }
  if ($PSBoundParameters.ContainsKey('Description')) { $all | Where-Object { $_.Description -eq $Description } }
  else { $all }
}

function Test-BarracudaConnected {
  try { (Get-VPNConnectionStatus -ErrorAction Stop).ConnectionState -eq 'ConnectStateConnected' } catch { $false }
}

function Get-VpnState {
  try { [string](Get-VPNConnectionStatus -ErrorAction Stop).ConnectionState } catch { '(nicht abfragbar)' }
}

function Get-VpnStatusText {
  try { (Get-VPNConnectionStatus -ErrorAction Stop | Out-String).Trim() } catch { '(Status nicht abfragbar)' }
}

# Connect-VPN may return before the tunnel is up; a gate waits for the adapter afterwards.
function Connect-BarracudaVpn {
  if ($Demo) { Write-Log "[DEMO] würde VPN-Profil '$VpnProfileName' verbinden"; return }
  Import-BarracudaModule
  if ((Test-BarracudaConnected) -and (Find-VpnAdapter)) { Write-Log 'VPN ist bereits verbunden'; return }

  $profiles = @(Find-VpnProfile)
  if ($profiles.Count -eq 0) {
    throw "VPN-Profil $(Get-VpnProfileLabel) nicht gefunden. Vorhanden: $((@(Get-BarracudaProfile).Description) -join ', ')"
  }
  if ($profiles.Count -gt 1) { Write-Log "WARNUNG: $($profiles.Count) Profile passen auf $(Get-VpnProfileLabel), nehme das erste ($($profiles[0].Description))" }
  $vpnProfile = $profiles[0]
  if ($DryRun) {
    Write-Log "[DRYRUN] Profil gefunden: '$($vpnProfile.Description)'. Würde das VPN verbinden"
    Write-DebugLog "Connect-VPN -ProfileID $($vpnProfile.ID) -ProfileContext $($vpnProfile.Context)"
    $script:VpnConnectPlanned = $true
    return
  }
  Write-Log "Verbinde VPN-Profil '$($vpnProfile.Description)'"
  Write-DebugLog "Connect-VPN -ProfileID $($vpnProfile.ID) -ProfileContext $($vpnProfile.Context)"
  try { Connect-VPN -ProfileID ([int]$vpnProfile.ID) -ProfileContext ([string]$vpnProfile.Context) -ErrorAction Stop | Out-Null }
  catch { Write-Log "Connect-VPN fehlgeschlagen: $($_.Exception.Message)"; throw }
}

# Disconnect-VPN blocks until the VPN is down and reports "VPN connection has been terminated!".
function Disconnect-ActiveVpn {
  if ($Demo) {
    Write-Ui '  VPN ist noch verbunden und wird getrennt in:' 'Yellow'
    foreach ($i in 3, 2, 1) { Write-Ui "    $i ..." 'Yellow'; Start-Sleep -Seconds 1 }
    Write-Log '[OK] VPN getrennt: VPN connection has been terminated! (Demo)' 'DarkGreen'
    return
  }
  if (-not ((Test-BarracudaConnected) -or (Find-VpnAdapter))) {
    Write-Log '[OK] Kein VPN aktiv, nichts zu trennen' 'DarkGreen'
    return
  }
  if ($DryRun) { Write-Log '[DRYRUN] VPN ist verbunden: würde nach Countdown 3-2-1 getrennt'; return }
  Write-Ui '  VPN ist noch verbunden und wird getrennt in:' 'Yellow'
  foreach ($i in 3, 2, 1) { Write-Ui "    $i ..." 'Yellow'; Start-Sleep -Seconds 1 }
  try {
    Import-BarracudaModule
    $message = (Disconnect-VPN -ErrorAction Stop | Out-String).Trim()
    Write-Log "[OK] VPN getrennt$(if ($message) { ": $message" })" 'DarkGreen'
  }
  catch { throw "VPN-Trennung fehlgeschlagen: $($_.Exception.Message)" }
}
#endregion

#region Internet Connection Sharing (COM: HNetCfg)
function Get-IcsConfiguration {
  param([string]$Name)
  regsvr32 /s hnetcfg.dll
  $manager = New-Object -ComObject HNetCfg.HNetShare
  foreach ($connection in $manager.EnumEveryConnection) {
    if ($manager.NetConnectionProps.Invoke($connection).Name -eq $Name) {
      return $manager.INetSharingConfigurationForINetConnection.Invoke($connection)
    }
  }
  throw "Adapter '$Name' nicht in HNetCfg gefunden"
}

# Turns ICS off on all adapters except Hyper-V/WSL (vEthernet*).
function Disable-AllIcs {
  if (-not $DryRun) { regsvr32 /s hnetcfg.dll }
  try { $manager = New-Object -ComObject HNetCfg.HNetShare }
  catch {
    if ($DryRun) { Write-Log "[DRYRUN] ICS-Schnittstelle nicht verfügbar: $($_.Exception.Message)"; return }
    throw
  }
  foreach ($connection in $manager.EnumEveryConnection) {
    $name = $manager.NetConnectionProps.Invoke($connection).Name
    if ($name -like 'vEthernet*') { continue }
    $config = $manager.INetSharingConfigurationForINetConnection.Invoke($connection)
    try {
      if ($config.SharingEnabled) {
        if ($DryRun) { Write-Log "[DRYRUN] würde ICS ausschalten: $name" }
        else { $config.DisableSharing(); Write-Log "ICS aus: $name" }
      }
    }
    catch { $null = $_ }
  }
}

function Get-IcsEnabledName {
  try {
    $manager = New-Object -ComObject HNetCfg.HNetShare
    foreach ($connection in $manager.EnumEveryConnection) {
      if ($manager.INetSharingConfigurationForINetConnection.Invoke($connection).SharingEnabled) { $manager.NetConnectionProps.Invoke($connection).Name }
    }
  }
  catch { "(nicht abfragbar: $($_.Exception.Message))" }
}

# Detects the three adapters and enables ICS: VPN (public) -> cable (private).
function Invoke-Share {
  if ($Demo) {
    Write-Log '[OK] ICS aktiv: Barracuda Virtual Adapter -> Ethernet (Demo)' 'DarkGreen'
    $script:Sum = @{ Wlan = 'WLAN'; Vpn = 'Barracuda Virtual Adapter'; Lan = 'Ethernet'; LanIndex = 0; Client2 = '192.168.137.2' }
    return
  }
  $vpn = if ($VpnAdapter) { Get-NetAdapter -Name $VpnAdapter -ErrorAction SilentlyContinue } else { Find-VpnAdapter }
  $inet = Find-InternetAdapter
  $lanState = if ($inet) { Get-LanState $inet.ifIndex } else { $null }
  $lan = if ($lanState) { $lanState.Adapter } else { $null }

  $problems = @()
  $expected = @()   # dry run only: missing because a skipped change would create it
  if (-not $vpn) {
    if ($DryRun -and $script:VpnConnectPlanned) { $expected += 'Noch kein VPN-Adapter: entsteht im echten Lauf durch Connect-VPN (Phase 4)' }
    else { $problems += "Kein aktiver VPN-Adapter ('$VpnPattern')" }
  }
  elseif ($vpn.Status -ne 'Up') { $problems += "VPN-Adapter '$($vpn.Name)' ist nicht Up ($($vpn.Status))" }
  if (-not $inet) { $problems += 'Kein Adapter mit Internetverbindung gefunden (WLAN verbunden?)' }
  elseif ($lanState.Problem) { $problems += $lanState.Problem }

  Write-DebugLog "Internet-Adapter : $(if ($inet) { $inet.Name } else { '(keiner)' })"
  Write-DebugLog "VPN-Adapter      : $(if ($vpn) { "$($vpn.Name) [$($vpn.InterfaceDescription)]" } else { '(keiner)' })"
  Write-DebugLog "LAN-Adapter      : $(if ($lan) { "$($lan.Name) [$($lan.InterfaceDescription)]" } else { '(keiner)' })"

  if ($problems.Count -gt 0) {
    if ($DryRun) { foreach ($problem in $problems) { Write-Log "[DRYRUN] PROBLEM: $problem" } }
    else { throw $problems[0] }
  }

  if ($DryRun) {
    foreach ($item in $expected) { Write-Log "[DRYRUN] erwartet: $item" }
    Write-Log '[DRYRUN] würde die Policies erneut setzen (falls die GPO zwischenzeitlich neu gegriffen hat)'
    Write-Log '[DRYRUN] würde Dienst SharedAccess auf Manuell stellen und starten'
    Disable-AllIcs
    if ($lan -and ($vpn -or $expected.Count -gt 0)) {
      $source = if ($vpn) { $vpn.Name } else { '<Barracuda-Adapter nach Connect>' }
      Write-Log "[DRYRUN] würde ICS aktivieren: $source (Quelle) -> $($lan.Name) (Ziel, 192.168.137.1)"
    }
    return
  }

  Disable-PolicyLock   # in case the GPO re-applied in the meantime
  Set-Service SharedAccess -StartupType Manual
  Start-Service SharedAccess
  Disable-AllIcs       # remove any old configuration
  $public = Get-IcsConfiguration $vpn.Name
  $private = Get-IcsConfiguration $lan.Name
  try {
    $public.EnableSharing(0)    # 0 = public  = source (VPN)
    $private.EnableSharing(1)   # 1 = private = target (cable to Client 2)
  }
  catch {
    Disable-AllIcs
    throw "EnableSharing fehlgeschlagen: $($_.Exception.Message)"
  }
  Write-Log "[OK] ICS aktiv: $($vpn.Name) -> $($lan.Name)" 'DarkGreen'
  Save-RunState "ICS aktiv: $($vpn.Name) -> $($lan.Name)"
  $script:Sum = @{ Wlan = $inet.Name; Vpn = $vpn.Name; Lan = $lan.Name; LanIndex = $lan.ifIndex }
  Start-Sleep -Seconds 3
  try {
    $ip = (Get-NetIPAddress -InterfaceIndex $lan.ifIndex -AddressFamily IPv4).IPAddress
    Write-DebugLog "Client 1 auf dem Kabel: $ip (Client 2 bekommt per DHCP 192.168.137.x)"
  }
  catch { $null = $_ }
}
#endregion

#region Prerequisites
# Kind 'hard' blocks the start, 'soft' is only a warning. Check returns '' (OK) or the problem text.
function Get-Prerequisite {
  @(
    @{ Kind = 'hard'; Name = 'Script als Administrator ausgeführt'; Check = { if (Test-Admin) { '' } else { 'PowerShell als Administrator starten' } } }
    @{ Kind = 'hard'; Name = 'Windows PowerShell 5.1'; Check = { if ($PSVersionTable.PSEdition -eq 'Desktop') { '' } else { 'PowerShell 7 erkannt' } } }
    @{ Kind = 'hard'; Name = 'WLAN-Adapter vorhanden'; Check = { $a = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -match '802\.11' }); if ($a.Count -eq 0) { 'kein WLAN-Adapter gefunden' } elseif (-not ($a | Where-Object { $_.Status -ne 'Disabled' })) { "'$($a[0].Name)' ist deaktiviert" } else { '' } } }
    @{ Kind = 'hard'; Name = 'Ethernet-Adapter vorhanden'; Check = { $a = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -notmatch '802\.11|Bluetooth' -and $_.InterfaceDescription -notmatch $VpnPattern }); if ($a.Count -eq 0) { 'kein Ethernet-Adapter gefunden (USB-Adapter gesteckt?)' } elseif (-not ($a | Where-Object { $_.Status -ne 'Disabled' })) { "'$($a[0].Name)' ist deaktiviert" } else { '' } } }
    @{ Kind = 'hard'; Name = 'Barracuda-VPN-Adapter vorhanden'; Check = { if (@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match $VpnPattern }).Count -gt 0) { '' } else { "kein Adapter '$VpnPattern' (Barracuda-Client installiert?)" } } }
    @{ Kind = 'hard'; Name = 'Barracuda-VPN-Profil vorhanden'; Check = {
        try { Import-BarracudaModule; if (@(Find-VpnProfile).Count -gt 0) { '' } else { "Profil $(Get-VpnProfileLabel) nicht gefunden" } }
        catch { $_.Exception.Message }
      }
    }
    @{ Kind = 'hard'; Name = 'WLAN hat Internet'; Check = {
        if (-not (Find-InternetAdapter)) { 'WLAN nicht verbunden' }
        elseif (-not (Test-TcpPort $InternetTestHost 80 5000)) { 'kein Internet (Anmeldeseite?)' }
        else { '' }
      }
    }
    @{ Kind = 'soft'; Name = 'Ethernet-Kabel schon gesteckt'; Check = {
        $routes = Get-DefaultRoute
        $bad = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
            $a = $_; $a.Status -eq 'Up' -and $a.PhysicalMediaType -notmatch '802\.11|Bluetooth' -and $a.InterfaceDescription -notmatch $VpnPattern -and ($routes | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }) })
        if ($bad.Count -gt 0) { "bitte abziehen ('$($bad[0].Name)')" } else { '' }
      }
    }
    @{ Kind = 'soft'; Name = 'Script liegt nicht lokal'; Check = { if ($PSScriptRoot -match '^\\\\|OneDrive|Downloads') { 'besser unter C:\Tools\vpn-share\ ablegen' } else { '' } } }
    @{ Kind = 'soft'; Name = 'VPN-Testziel nicht konfiguriert'; Check = { if ($VpnTestHost -or $env:USERDNSDOMAIN -or $env:LOGONSERVER) { '' } else { 'kein Domänen-Client: VpnTestHost in vpn-share.config.json setzen' } } }
    @{ Kind = 'soft'; Name = 'Frühere Änderungen noch aktiv'; Check = { if (Test-Path $StateFile) { 'bitte -Step Off ausführen' } else { '' } } }
    @{ Kind = 'soft'; Name = 'Achtung: VPN auf Client 1 aktiv'; Check = { if ((Test-BarracudaConnected) -or (Find-VpnAdapter)) { 'wird nach dem Start getrennt' } else { '' } } }
  )
}

# Runs all checks, draws the panel and returns the number of hard failures.
function Show-PrerequisitePanel {
  $okMark = [string][char]0x2714
  $failMark = [string][char]0x2718
  $script:DemoPanelRuns++
  $results = foreach ($item in (Get-Prerequisite)) {
    if ($Demo) {   # simulated results: VPN still connected (shows the countdown); with -DemoFail the first panel has one failure
      $problem = ''
      if ($item.Name -eq 'Achtung: VPN auf Client 1 aktiv') { $problem = 'wird nach dem Start getrennt' }
      if ($DemoFail -and $script:DemoPanelRuns -eq 1 -and $item.Name -eq 'WLAN hat Internet') { $problem = 'kein Internet (Anmeldeseite?)' }
    }
    else { $problem = try { [string](& $item.Check) } catch { $_.Exception.Message } }
    [pscustomobject]@{ Kind = $item.Kind; Name = $item.Name; Problem = $problem }
  }
  Write-PanelBorder 'top' 'Voraussetzungen Client 1'
  foreach ($result in $results) {
    if (-not $result.Problem) { if ($result.Kind -eq 'hard') { Write-PanelLine "[$okMark] $($result.Name)" 'DarkGreen' } }   # soft checks only show when they warn
    elseif ($result.Kind -eq 'soft') { Write-PanelLine "[!] $($result.Name) - $($result.Problem)" 'Yellow' }
    else { Write-PanelLine "[$failMark] $($result.Name) - $($result.Problem)" 'Red' }
    if ($result.Problem) { try { Add-Content -Path $LogFile -Value ('{0:yyyy-MM-dd HH:mm:ss}  PRÜFUNG {1}: {2}' -f (Get-Date), $result.Name, $result.Problem) -Encoding UTF8 } catch { $null = $_ } }
  }
  Write-PanelBorder 'mid' 'Vom Admin zu bestätigen'
  Write-PanelLine '-> Client 2 ist eingeschaltet, hochgefahren und einsatzbereit' 'Cyan'
  Write-PanelLine '-> WLAN an Client 2 ist getrennt/ausgeschaltet' 'Cyan'
  Write-PanelLine '-> Patchkabel liegt bereit (später direkt Client 1 <-> Client 2)' 'Cyan'
  Write-PanelLine '-> BIOS Client 1: Wireless Radio Control -> Control WLAN radio aus' 'Cyan'
  Write-PanelBorder 'bottom'
  @($results | Where-Object { $_.Problem -and $_.Kind -eq 'hard' }).Count
}

function Confirm-Prerequisite {
  Write-Log '=== 0/6 Voraussetzungen ==='
  while ($true) {
    $failures = Show-PrerequisitePanel
    if ($DryRun) { Disconnect-ActiveVpn; return }
    if ($failures -gt 0) {
      Write-Ui ('  ' + [char]0x2718 + " $failures Voraussetzung(en) nicht erfüllt") 'Red'
      $answer = Read-Choice 'Ursache beheben, dann Prüfung wiederholen' '[Enter]/[R] Prüfung wiederholen     [N] Abbruch' 'Error'
      if ($answer -match '^[nNaA]') { throw 'Abbruch bei: Voraussetzungen' }
      continue
    }
    Write-Ui ('  ' + [char]0x2714 + ' Alle Prüfungen bestanden') 'DarkGreen'
    $answer = Read-Choice 'Prozess starten?' '[Enter] Start     [R] Prüfung wiederholen     [N] Abbruch'
    if ($answer -match '^[nNaA]') { throw 'Abbruch bei: Voraussetzungen' }
    if ($answer -match '^[rR]') { continue }
    break
  }
  Write-Log '[OK] Voraussetzungen bestätigt, Start' 'DarkGreen'
  Disconnect-ActiveVpn
}
#endregion

#region Teardown and diagnostics
function Invoke-Off {
  if ($Demo) { Write-Log '[DEMO] würde ICS ausschalten, VPN trennen und gpupdate /force ausführen'; return }
  Disable-AllIcs
  if (-not $KeepVpn) {
    try {
      Import-BarracudaModule
      if (Test-BarracudaConnected) {
        if ($DryRun) { Write-Log '[DRYRUN] würde VPN trennen (Disconnect-VPN)' }
        else { Disconnect-VPN -ErrorAction Stop; Start-Sleep -Seconds 3; Write-Log 'VPN getrennt' }
      }
      else { Write-Log 'VPN war nicht verbunden' }
    }
    catch { Write-Log "VPN-Trennung fehlgeschlagen: $($_.Exception.Message)" }
  }
  if ($DryRun) { Write-Log '[DRYRUN] würde gpupdate /force ausführen (holt die Original-Policies zurück)' }
  else {
    gpupdate /force | Out-Null   # the GPO restores the original policies
    Remove-RunState
    Write-Log '[OK] ICS aus, Policies per gpupdate wiederhergestellt (Backups: C:\*-policy-backup.reg)' 'DarkGreen'
  }
}

# Read-only snapshot, shown with -DryRun -DebugInfo.
function Show-Diagnostic {
  Write-Log '--- Ist-Zustand (nur lesen) ---'
  Write-Log "PowerShell: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion) | Script: $PSCommandPath"
  Show-PolicyPlan
  foreach ($name in 'WlanSvc', 'SharedAccess') {
    $service = Get-Service $name -ErrorAction SilentlyContinue
    if ($service) { Write-Log "Dienst $name : $($service.Status), Starttyp $($service.StartType)" }
  }
  $routes = Get-DefaultRoute
  foreach ($adapter in (Get-NetAdapter | Sort-Object ifIndex)) {
    $hasRoute = [bool]($routes | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex })
    Write-Log ('Adapter {0,-26} {1,-13} Default-Route={2,-5} {3} [{4}]' -f $adapter.Name, $adapter.Status, $hasRoute, $adapter.PhysicalMediaType, $adapter.InterfaceDescription)
  }
  Write-Log "ICS aktiv auf: $((@(Get-IcsEnabledName)) -join ', ')"
  try {
    Import-BarracudaModule
    $found = @(Find-VpnProfile)
    if ($found.Count -eq 0) { Write-Log "Barracuda-Profil $(Get-VpnProfileLabel): NICHT gefunden. Vorhanden: $((@(Get-BarracudaProfile).Description) -join ', ')" }
    else { Write-Log "Barracuda-Profil $(Get-VpnProfileLabel): gefunden (ID=$($found[0].ID), Context=$($found[0].Context), Anzahl=$($found.Count))" }
    Write-Log "Barracuda Verbindungsstatus: $(Get-VpnState)"
  }
  catch { Write-Log "Barracuda: PROBLEM: $($_.Exception.Message)" }
  Write-Log '--- Ende Ist-Zustand ---'
}
#endregion

#region Main flow
function Invoke-AutoRun {
  Confirm-Prerequisite
  $startTime = Get-Date

  # Phase 1: policies (admin: nothing to do, WLAN stalls 10-20 s)
  Write-Log '=== 1/6 Policies ==='
  Invoke-Safe { Invoke-Prep }

  # Phase 2: internet over WLAN
  Write-Log '=== 2/6 Internet über WLAN ==='
  Invoke-Gate -Title 'WLAN verbunden (mit Internetverbindung)' -TimeoutSec 120 `
    -Hint 'WLAN verbinden, falls es sich nicht selbst verbindet' `
    -Check { if (Find-InternetAdapter) { '' } else { 'WLAN nicht verbunden bzw. ohne Internetverbindung' } }
  $script:InetIdx = Get-InetIndex   # from now on this exact WLAN is monitored
  $script:Ssid = Get-CurrentSsid
  if ($script:Ssid) { Write-DebugLog "Aktuelles WLAN: $($script:Ssid)" }
  Invoke-Gate -Title "Internet erreichbar ($InternetTestHost)" -AllowSkip `
    -Hint 'Falls Anmeldeseite: im Browser anmelden' `
    -Check { if (Test-TcpPort $InternetTestHost 80) { '' } else { 'keine Verbindung' } }

  # Phase 3: cable to Client 2 (never into a wall socket or switch)
  Write-Log '=== 3/6 Kabel zu Client 2 ==='
  Invoke-Gate -Title 'Kabel direkt zu Client 2' -TimeoutSec 180 `
    -Hint 'Kabel jetzt direkt von Client 1 zu Client 2 stecken, Client 2 einschalten (nicht ins Standort-Netz!)' `
    -Check { [string](Get-LanState (Get-InetIndex)).Problem }
  Restore-Wlan
  Invoke-Gate -Title 'WLAN nach Kabel weiter verbunden' -TimeoutSec 90 `
    -Hint "Fällt WLAN beim Kabelstecken aus: BIOS 'Wireless Radio Control' prüfen" `
    -Check { if (Test-InetUp) { '' } else { 'WLAN weg' } }

  # Phase 4: VPN (admin: nothing to do, tunnel needs up to 180 s)
  Write-Log '=== 4/6 VPN ==='
  Invoke-Safe { Connect-BarracudaVpn }
  Invoke-Gate -Title 'Barracuda-VPN-Adapter Up' -TimeoutSec 180 -AfterChange `
    -Hint 'VPN baut auf, bitte warten' `
    -Check { if (Find-VpnAdapter) { '' } else { "VPN-Adapter nicht Up. Status: $(Get-VpnStatusText)" } }
  Restore-Wlan   # the GPO (fBlockNonDomain) may drop the WLAN after the VPN connects
  Invoke-Gate -Title 'WLAN nach VPN-Connect weiter verbunden' -TimeoutSec 90 `
    -Hint 'Fällt WLAN hier aus: Policy fBlockNonDomain greift wieder, Script erneut starten' `
    -Check { if (Test-InetUp) { '' } else { 'WLAN weg, Tunnel bricht ab' } }
  Invoke-Gate -Title 'Barracuda meldet: VPN verbunden' -TimeoutSec 120 -AfterChange `
    -Hint 'Prüft den Verbindungsstatus des Barracuda-Clients' `
    -Check { if (Test-BarracudaConnected) { '' } else { "Status: $(Get-VpnState)" } }
  if (-not $VpnTestHost) {
    $dc = Find-DomainController
    if ($dc) {
      $script:VpnTestHost = $dc
      if (-not $VpnTestPort) { $script:VpnTestPort = 389 }
      Write-Log "VPN-Testziel automatisch ermittelt (Domain Controller): ${VpnTestHost}:$VpnTestPort"
    }
  }
  if ($VpnTestHost) {
    Invoke-Gate -Title "VPN-Testziel auflösbar ($VpnTestHost)" -AllowSkip -AfterChange `
      -Hint 'Prüft, ob das VPN auf Client 1 wirklich funktioniert' `
      -Check { try { Resolve-DnsName $VpnTestHost -ErrorAction Stop | Out-Null; '' } catch { 'DNS-Auflösung scheitert' } }
    if ($VpnTestPort) {
      Invoke-Gate -Title "VPN-Testziel erreichbar (${VpnTestHost}:$VpnTestPort)" -AllowSkip -AfterChange `
        -Hint 'Prüft die Verbindung durch den Tunnel (TCP)' `
        -Check { if (Test-TcpPort $VpnTestHost $VpnTestPort 5000) { '' } else { 'keine Verbindung durch den Tunnel' } }
    }
  }
  else { Write-Log 'Achtung: Kein VpnTestHost konfiguriert, der Funktionstest des VPN entfällt' 'Yellow' }

  # Phase 5: enable ICS
  Write-Log '=== 5/6 Weitergabe (ICS) ==='
  Invoke-Safe { Invoke-Share }

  # Phase 6: wrap-up
  Write-Log '=== 6/6 Fertig ==='
  if ($DryRun) { return }

  # ICS hands out 192.168.137.x via DHCP; Client 2 shows up as a neighbor on the cable adapter
  Invoke-Gate -Title 'Client 2 hat Adresse per DHCP (192.168.137.x)' -TimeoutSec 90 -AllowSkip `
    -Hint 'Client 2: Ethernet-Adapter auf DHCP stellen bzw. Kabel kurz neu stecken' `
    -Check {
      $neighbor = Get-NetNeighbor -InterfaceIndex $script:Sum.LanIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like '192.168.137.*' -and $_.IPAddress -ne '192.168.137.1' -and $_.State -notin 'Unreachable', 'Incomplete' } |
        Select-Object -First 1
      if ($neighbor) { $script:Sum.Client2 = $neighbor.IPAddress; '' } else { 'noch keine Adresse gesehen' }
    }

  $okMark = [string][char]0x2714
  Write-PanelBorder 'top' 'Zusammenfassung'
  Write-PanelLine "[$okMark] WLAN (Internet):   $($script:Sum.Wlan)" 'DarkGreen'
  Write-PanelLine "[$okMark] VPN-Adapter:       $($script:Sum.Vpn)" 'DarkGreen'
  Write-PanelLine "[$okMark] Kabel zu Client 2: $($script:Sum.Lan) (192.168.137.1)" 'DarkGreen'
  if ($script:Sum.Client2) { Write-PanelLine "[$okMark] Client 2:          $($script:Sum.Client2)" 'DarkGreen' }
  else { Write-PanelLine '[!] Client 2 noch nicht gesehen, an Client 2 testen' 'Yellow' }
  Write-PanelLine ('Dauer: {0:mm\:ss}' -f ((Get-Date) - $startTime)) 'Gray'
  Write-PanelBorder 'bottom'
  Write-Log "Log: $LogFile"
  if ($VpnTestHost) { Write-Log "Test an Client 2: ping $VpnTestHost" }
  else { Write-Log 'Test an Client 2: Internet bzw. interne Ressource aufrufen' }
  Write-Log '[OK] Weitergabe läuft' 'DarkGreen'

  $answer = Read-Choice 'Rückbau (-Step Off) jetzt ausführen?' '[Enter] Ja, zurückbauen     [N] Später (erst nach dem Test an Client 2)'
  if ($answer -notmatch '^[nN]') { Invoke-Off }
  else { Write-Log 'Rückbau später mit: vpn-share.ps1 -Step Off' }
}

function Invoke-Main {
  if ($Demo) {
    if (-not $VpnProfileName) { $script:VpnProfileName = 'DemoProfil' }
    if (-not $VpnTestHost) { $script:VpnTestHost = 'intern.example.com' }
    Write-Log "===== DEMO: Ablauf wird nur SIMULIERT, es wird nichts geändert (Log: $LogFile) ====="
  }
  elseif (-not (Test-Admin)) { throw 'Nicht als Administrator gestartet. PowerShell als Administrator öffnen und erneut starten' }
  if ($DryRun) {
    Write-Log "===== TROCKENLAUF: Es wird NICHTS am System geändert (Log: $LogFile) ====="
    if ($DebugInfo) { Show-Diagnostic }
  }
  switch ($Step) {
    'Prep' { Invoke-Safe { Invoke-Prep } }
    'Share' { Invoke-Safe { Invoke-Share } }
    'Off' { Invoke-Off }
    'Auto' { Invoke-AutoRun }
  }
  if ($Demo) { Write-Log '===== DEMO ENDE: Es wurde nichts geändert =====' }
  if ($DryRun) { Write-Log '===== TROCKENLAUF ENDE: Es wurde NICHTS geändert. [DRYRUN]-Zeilen zeigen, was im echten Lauf passiert =====' }
}

try { Invoke-Main }
catch {
  # Every error (including "abort" via A) lands here; cleanup is offered, not forced, so the admin can inspect first.
  Write-Log "ABBRUCH: $($_.Exception.Message)" 'Red'
  if ($Step -ne 'Off' -and -not $DryRun -and -not $Demo -and (Test-Path $StateFile)) {
    $answer = Read-Choice 'Änderungen sind noch aktiv - jetzt zurückbauen (-Step Off)?' '[Enter] Ja, zurückbauen     [N] Später' 'Error'
    if ($answer -notmatch '^[nN]') { try { Invoke-Off } catch { Write-Log "Rückbau fehlgeschlagen: $($_.Exception.Message)" } }
    else { Write-Log 'Aufräumen später mit: -Step Off' }
  }
  elseif ($Step -eq 'Off') { Write-Log 'Rückbau unvollständig: -Step Off erneut ausführen' }
  if ($PSCommandPath) { exit 1 } else { return }   # exit would close the console when started from memory
}
#endregion
