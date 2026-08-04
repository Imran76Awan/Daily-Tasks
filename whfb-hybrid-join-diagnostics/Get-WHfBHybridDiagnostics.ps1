#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Windows Hello for Business diagnostic data from a Hybrid-joined device.

.DESCRIPTION
    Read-only diagnostic script. Collects device join state, PRT status, WHfB event log
    entries (Event 360, AAD operational errors), and optionally triggers a PRT refresh to
    test whether the domain controller is reachable. Output is formatted ready to paste
    into a support ticket.

    Companion to:
      Blog:   https://endpointweekly.com/blog/whfb-hybrid-join-prt-diagnostic-walkthrough.html
      Catalog: https://endpointweekly.com/blog/whfb-event-id-catalog.html

.NOTES
    Author  : Imran Awan
    Version : 1.0
    Date    : 2026-08-04
    Repo    : https://github.com/Imran76Awan/Daily-Tasks/tree/main/whfb-hybrid-join-diagnostics

    Run as the signed-in user (not SYSTEM / admin) so dsregcmd reflects the
    current user session. The AAD/Operational log requires admin rights to read -
    the script will skip that section gracefully if not elevated.
#>

[CmdletBinding()]
param (
    [switch]$RefreshPRT,    # Add -RefreshPRT to also run dsregcmd /refreshprt
    [switch]$ExportTxt,     # Add -ExportTxt to save output to a file on the Desktop
    [switch]$SkipEventLogs  # Add -SkipEventLogs to skip Get-WinEvent calls (faster on slow devices)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Section ([string]$Title) {
    $line = '─' * 70
    Write-Host "`n$line" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor DarkGray
}

function Write-Field ([string]$Label, [string]$Value, [string]$Expect = '') {
    $colour = 'White'
    if ($Expect -and $Value -eq $Expect) { $colour = 'Green' }
    elseif ($Expect -and $Value -ne $Expect) { $colour = 'Red' }
    Write-Host ("  {0,-32} {1}" -f $Label, $Value) -ForegroundColor $colour
}

function Get-DsregField ([string[]]$Output, [string]$Field) {
    $line = $Output | Where-Object { $_ -match "^\s*$([regex]::Escape($Field))\s*:" } | Select-Object -First 1
    if ($line) { return ($line -split ':', 2)[1].Trim() }
    return ''
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Capture output for optional export ─────────────────────────────────────────

$capture = [System.Collections.Generic.List[string]]::new()
if ($ExportTxt) {
    # Tee console output to a list so we can write to file at the end
    $null = $capture  # populated via transcript below
    $transcript = "$env:USERPROFILE\Desktop\WHfB-Diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    Start-Transcript -Path $transcript -Force | Out-Null
}

# ── Header ─────────────────────────────────────────────────────────────────────

Clear-Host
Write-Host @"

  ██╗    ██╗██╗  ██╗███████╗██████╗     ██████╗ ██╗ █████╗  ██████╗
  ██║    ██║██║  ██║██╔════╝██╔══██╗    ██╔══██╗██║██╔══██╗██╔════╝
  ██║ █╗ ██║███████║█████╗  ██████╔╝    ██║  ██║██║███████║██║  ███╗
  ██║███╗██║██╔══██║██╔══╝  ██╔══██╗    ██║  ██║██║██╔══██║██║   ██║
  ╚███╔███╔╝██║  ██║██║     ██████╔╝    ██████╔╝██║██║  ██║╚██████╔╝
   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═════╝     ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝

"@ -ForegroundColor DarkGreen

Write-Host "  WHfB Hybrid Join Diagnostics" -ForegroundColor White
Write-Host "  endpointweekly.com/blog/whfb-hybrid-join-prt-diagnostic-walkthrough.html" -ForegroundColor DarkGray
Write-Host "  $(Get-Date -Format 'dddd dd MMMM yyyy HH:mm:ss')  |  $env:COMPUTERNAME  |  $env:USERNAME`n" -ForegroundColor DarkGray

if (-not (Test-IsElevated)) {
    Write-Host "  [!] Not running as Administrator. AAD/Operational event log will be skipped." -ForegroundColor Yellow
    Write-Host "      Re-run elevated to include AAD error codes.`n" -ForegroundColor DarkGray
}

# ── Section 1: dsregcmd /status ────────────────────────────────────────────────

Write-Section "1 of 5 — Device Join State  (dsregcmd /status)"

$dsreg = & dsregcmd /status 2>&1

$azureAdJoined    = Get-DsregField $dsreg 'AzureAdJoined'
$domainJoined     = Get-DsregField $dsreg 'DomainJoined'
$deviceName       = Get-DsregField $dsreg 'DeviceName'
$tenantName       = Get-DsregField $dsreg 'TenantName'
$tenantId         = Get-DsregField $dsreg 'TenantId'
$ngcSet           = Get-DsregField $dsreg 'NgcSet'
$ngcKeyId         = Get-DsregField $dsreg 'NgcKeyId'

Write-Field 'DeviceName'       $deviceName
Write-Field 'TenantName'       $tenantName
Write-Field 'TenantId'         $tenantId
Write-Host ''
Write-Field 'AzureAdJoined'    $azureAdJoined    'YES'
Write-Field 'DomainJoined'     $domainJoined     'YES'

$joinType = switch -Regex ("$azureAdJoined|$domainJoined") {
    'YES\|YES' { 'Hybrid Joined  ✓' }
    'YES\|NO'  { 'Entra-only (Cloud Join)' }
    'NO\|YES'  { 'On-premises only' }
    default    { 'Unknown / Not joined' }
}
Write-Host ("  {0,-32} {1}" -f 'Join type', $joinType) -ForegroundColor $(if ($azureAdJoined -eq 'YES' -and $domainJoined -eq 'YES') { 'Green' } else { 'Yellow' })

Write-Host ''
Write-Field 'NgcSet (WHfB enrolled)'  $ngcSet  'YES'
if ($ngcKeyId) {
    Write-Host ("  {0,-32} {1}" -f 'NgcKeyId', $ngcKeyId) -ForegroundColor DarkGray
} else {
    Write-Host "  NgcKeyId                         (not present — WHfB not enrolled)" -ForegroundColor Red
}

# ── Section 2: PRT state ───────────────────────────────────────────────────────

Write-Section "2 of 5 — Primary Refresh Token (PRT) State"

$azureAdPrt           = Get-DsregField $dsreg 'AzureAdPrt'
$azureAdPrtUpdateTime = Get-DsregField $dsreg 'AzureAdPrtUpdateTime'
$azureAdPrtExpiry     = Get-DsregField $dsreg 'AzureAdPrtExpiryTime'
$enterprisePrt        = Get-DsregField $dsreg 'EnterprisePrt'
$enterprisePrtExpiry  = Get-DsregField $dsreg 'EnterprisePrtExpiryTime'

Write-Field 'AzureAdPrt'              $azureAdPrt       'YES'
Write-Field 'AzureAdPrtUpdateTime'    $azureAdPrtUpdateTime
Write-Field 'AzureAdPrtExpiryTime'    $azureAdPrtExpiry
Write-Host ''
Write-Field 'EnterprisePrt'           $enterprisePrt    'YES'
if ($enterprisePrtExpiry) {
    Write-Field 'EnterprisePrtExpiryTime' $enterprisePrtExpiry
}

# Parse and evaluate PRT freshness
if ($azureAdPrtExpiry) {
    try {
        # dsregcmd outputs time in format like "2026-08-04 08:00:00.000 UTC"
        $expiry = [datetime]::ParseExact(
            ($azureAdPrtExpiry -replace '\s+UTC','').Trim(),
            'yyyy-MM-dd HH:mm:ss.fff',
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        $hoursLeft = [math]::Round(($expiry.ToUniversalTime() - [datetime]::UtcNow).TotalHours, 1)
        $freshMsg  = if ($hoursLeft -gt 0) { "Expires in $hoursLeft hours" } else { "EXPIRED $([math]::Abs($hoursLeft)) hours ago" }
        $freshCol  = if ($hoursLeft -gt 0) { 'Green' } else { 'Red' }
        Write-Host ("  {0,-32} {1}" -f 'PRT validity', $freshMsg) -ForegroundColor $freshCol
    } catch { }
}

Write-Host ''
if ($enterprisePrt -ne 'YES') {
    Write-Host "  [!] EnterprisePrt: NO — on-premises SSO will fail." -ForegroundColor Red
    Write-Host "      Likely cause: device cannot reach a domain controller." -ForegroundColor Yellow
    Write-Host "      Run this script on VPN with -RefreshPRT to confirm." -ForegroundColor DarkGray
}

# ── Section 3: WHfB event log ──────────────────────────────────────────────────

Write-Section "3 of 5 — WHfB Event Timeline (User Device Registration + HelloForBusiness)"

if ($SkipEventLogs) {
    Write-Host "  [Skipped — -SkipEventLogs flag set]" -ForegroundColor DarkGray
} else {
    $whfbLogs = @(
        'Microsoft-Windows-User Device Registration/Admin',
        'Microsoft-Windows-HelloForBusiness/Operational'
    )

    $whfbIdMap = @{
        358  = 'Provisioning will be launched'
        360  = 'Provisioning will NOT be launched (prereq failed)'
        362  = 'Provisioning complete'
        363  = 'Provisioning failed (NGC key missing)'
        5205 = 'WHfB config loaded'
        5702 = 'WHfB keys written to disk'
        3520 = 'Device unlock attempt initiated'
        5520 = 'Device unlock policy not configured'
        7520 = 'Device unlock error'
        8520 = 'Device unlock success'
    }

    $events = foreach ($log in $whfbLogs) {
        try {
            Get-WinEvent -LogName $log -MaxEvents 50 -ErrorAction Stop |
                Where-Object { $_.Id -in $whfbIdMap.Keys }
        } catch { }
    }

    if ($events) {
        $events | Sort-Object TimeCreated | ForEach-Object {
            $colour = switch ($_.Id) {
                360     { 'Yellow' }
                { $_ -in 358,362,5702,8520 } { 'Green' }
                { $_ -in 363,7520 } { 'Red' }
                default { 'Gray' }
            }
            $level = if ($_.Id -eq 360) { 'WARN ' } elseif ($_.LevelDisplayName -eq 'Error') { 'ERROR' } else { 'INFO ' }
            Write-Host ("  {0}  {1}  [{2}]  {3}" -f `
                $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'),
                $level,
                $_.Id,
                $whfbIdMap[$_.Id]) -ForegroundColor $colour
        }
    } else {
        Write-Host "  No relevant WHfB events found in the last 50 entries." -ForegroundColor DarkGray
    }
}

# ── Section 4: Event 360 full messages ─────────────────────────────────────────

Write-Section "4 of 5 — Event 360 Full Messages (last 3)"

if ($SkipEventLogs) {
    Write-Host "  [Skipped — -SkipEventLogs flag set]" -ForegroundColor DarkGray
} else {
    try {
        $ev360 = Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -ErrorAction Stop |
            Where-Object Id -eq 360 |
            Select-Object -First 3

        if ($ev360) {
            foreach ($e in $ev360) {
                Write-Host "`n  Time: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
                # Extract and colour each prereq line
                $e.Message -split "`n" | ForEach-Object {
                    $trimmed = $_.Trim()
                    if (-not $trimmed) { return }
                    if ($trimmed -match ':\s*No$') {
                        Write-Host "    $trimmed" -ForegroundColor Red
                    } elseif ($trimmed -match ':\s*Yes$') {
                        Write-Host "    $trimmed" -ForegroundColor Green
                    } else {
                        Write-Host "    $trimmed" -ForegroundColor DarkGray
                    }
                }
            }
        } else {
            Write-Host "  No Event 360 entries found." -ForegroundColor Green
            Write-Host "  WHfB provisioning has not been blocked recently." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  Could not read User Device Registration log: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# ── Section 5: AAD operational error codes ─────────────────────────────────────

Write-Section "5 of 5 — AAD/Operational Event Log (error codes)"

if ($SkipEventLogs) {
    Write-Host "  [Skipped — -SkipEventLogs flag set]" -ForegroundColor DarkGray
} elseif (-not (Test-IsElevated)) {
    Write-Host "  [Skipped — requires Administrator rights]" -ForegroundColor Yellow
    Write-Host "  Re-run elevated to see AAD/Operational error codes (0xc000023c, 0x8007054B etc.)" -ForegroundColor DarkGray
} else {
    $knownCodes = @{
        '0xc000023c' = 'STATUS_NO_LOGON_SERVERS — no DC reachable'
        '0x80072ee7' = 'ERROR_WINHTTP_NAME_NOT_RESOLVED — DNS failure / no network'
        '0x8007054b' = 'Cannot get domain name — DC lookup failed'
        '0xcaa90022' = 'ADFS IWA endpoint not discoverable — expected noise on Okta/non-ADFS'
        '0xcaa9002b' = 'WS-Trust MEX exchange failed'
        '0x80070005' = 'Access denied'
        '0xcaa82ee7' = 'Network name not resolved (Azure AD token request)'
    }

    try {
        $aadEvents = Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 60 -ErrorAction Stop |
            Where-Object { $_.Id -in 1097, 1098 }

        if ($aadEvents) {
            $foundCodes = [System.Collections.Generic.HashSet[string]]::new()

            foreach ($e in ($aadEvents | Sort-Object TimeCreated)) {
                $msg = $e.Message
                # Extract all hex error codes from the message
                $codes = [regex]::Matches($msg, '0x[0-9a-fA-F]{6,8}') | ForEach-Object { $_.Value.ToLower() }
                foreach ($code in $codes) {
                    $null = $foundCodes.Add($code)
                }

                # Print only events that contain a known bad code
                $hasBad = $codes | Where-Object { $knownCodes.ContainsKey($_) }
                if ($hasBad) {
                    $level  = if ($e.Id -eq 1098) { 'ERROR' } else { 'WARN ' }
                    $colour = if ($e.Id -eq 1098) { 'Red' } else { 'Yellow' }
                    Write-Host ("  {0}  {1}  [ID:{2}]" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $level, $e.Id) -ForegroundColor $colour
                    foreach ($code in $hasBad) {
                        Write-Host ("    {0,-14} {1}" -f $code, $knownCodes[$code]) -ForegroundColor Red
                    }
                }
            }

            if ($foundCodes.Count -eq 0) {
                Write-Host "  No known error codes found in last 60 AAD events." -ForegroundColor Green
            }
        } else {
            Write-Host "  No AAD operational events (ID 1097/1098) found." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  Could not read AAD/Operational log: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# ── Optional: PRT refresh test ─────────────────────────────────────────────────

if ($RefreshPRT) {
    Write-Section "BONUS — PRT Refresh Test  (dsregcmd /refreshprt)"
    Write-Host "  Requesting PRT refresh..." -ForegroundColor DarkGray
    & dsregcmd /refreshprt 2>&1 | Out-Null
    Start-Sleep -Seconds 20
    Write-Host "  Re-checking PRT state after refresh:`n" -ForegroundColor DarkGray

    $dsreg2          = & dsregcmd /status 2>&1
    $newEnterprisePrt = Get-DsregField $dsreg2 'EnterprisePrt'
    $newExpiry        = Get-DsregField $dsreg2 'AzureAdPrtExpiryTime'

    Write-Field 'EnterprisePrt (after refresh)' $newEnterprisePrt 'YES'
    Write-Field 'AzureAdPrtExpiryTime (after)'  $newExpiry

    if ($newEnterprisePrt -eq 'YES') {
        Write-Host "`n  [+] EnterprisePrt is now YES — DC is reachable on this connection." -ForegroundColor Green
        Write-Host "      The PRT failure happens at login time when the device has no network." -ForegroundColor DarkGray
    } else {
        Write-Host "`n  [!] EnterprisePrt is still NO after refresh." -ForegroundColor Red
        Write-Host "      The device cannot reach a domain controller on this connection." -ForegroundColor Yellow
        Write-Host "      Check:" -ForegroundColor DarkGray
        Write-Host "        1. VPN split-tunnel routing — DC subnet IPs must be in the tunnel" -ForegroundColor DarkGray
        Write-Host "        2. Internal DNS must resolve from within the VPN tunnel" -ForegroundColor DarkGray
        Write-Host "        3. UDP 88 (Kerberos) must not be blocked between VPN pool and DC subnet" -ForegroundColor DarkGray
    }

    if ($newExpiry -and $azureAdPrtExpiry -and $newExpiry -ne $azureAdPrtExpiry) {
        Write-Host "`n  [+] AzureAdPrtExpiryTime extended — Azure AD PRT is refreshing correctly." -ForegroundColor Green
    }
}

# ── Summary ─────────────────────────────────────────────────────────────────────

Write-Section "Summary"

$issues   = [System.Collections.Generic.List[string]]::new()
$findings = [System.Collections.Generic.List[string]]::new()

if ($azureAdJoined -eq 'YES' -and $domainJoined -eq 'YES') {
    $null = $findings.Add("Device is Hybrid Joined (AzureAdJoined + DomainJoined = YES)")
} else {
    $null = $issues.Add("Device is NOT Hybrid Joined — check join state before proceeding")
}

if ($ngcSet -eq 'YES') {
    $null = $findings.Add("WHfB is enrolled (NgcSet: YES, key present)")
} else {
    $null = $issues.Add("WHfB not enrolled — NgcSet: NO, provisioning has not completed")
}

if ($azureAdPrt -eq 'YES') {
    $null = $findings.Add("Azure AD PRT exists (AzureAdPrt: YES)")
} else {
    $null = $issues.Add("No Azure AD PRT — device cannot authenticate to Entra ID")
}

if ($enterprisePrt -ne 'YES') {
    $null = $issues.Add("EnterprisePrt: NO — domain controller unreachable, on-premises SSO broken")
}

if ($findings.Count -gt 0) {
    Write-Host "`n  OK:" -ForegroundColor Green
    $findings | ForEach-Object { Write-Host "    + $_" -ForegroundColor Green }
}

if ($issues.Count -gt 0) {
    Write-Host "`n  Issues found:" -ForegroundColor Red
    $issues | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ''
    Write-Host "  Next step: follow the walkthrough at" -ForegroundColor Yellow
    Write-Host "  https://endpointweekly.com/blog/whfb-hybrid-join-prt-diagnostic-walkthrough.html" -ForegroundColor Cyan
} else {
    Write-Host "`n  No issues detected in this diagnostic run." -ForegroundColor Green
}

Write-Host ''
Write-Host ('─' * 70) -ForegroundColor DarkGray
Write-Host "  EndpointWeekly  |  endpointweekly.com" -ForegroundColor DarkGray
Write-Host ''

# ── Export ──────────────────────────────────────────────────────────────────────

if ($ExportTxt) {
    Stop-Transcript | Out-Null
    Write-Host "  Output saved to: $transcript" -ForegroundColor Cyan
}
