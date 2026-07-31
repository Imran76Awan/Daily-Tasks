<#
.SYNOPSIS
    Read-only reader for Windows Hello for Business trusted signal (multifactor)
    device unlock configuration and recent Device Unlock events.

.DESCRIPTION
    Changes nothing. Reports:
      1. The DeviceUnlock policy under the PassportForWork registry tree, if present,
         mapping the configured first/second unlock factor GUIDs to friendly names.
      2. Recent events from the HelloForBusiness/Operational log, Device Unlock
         category (event IDs 3520/5520/6520/7520/8520).

    Use it to confirm the unlock policy actually applied and to see whether real
    unlock attempts are succeeding (8520) or failing (7520) / unconfigured (5520).

.PARAMETER MaxEvents
    How many recent Device Unlock events to show. Default 20.

.EXAMPLE
    .\Get-DeviceUnlockConfig.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-multifactor-device-unlock.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param([int]$MaxEvents = 20)

$providerNames = @{
    '{D6886603-9D2F-4EB2-B667-1971041FA96B}' = 'PIN'
    '{BEC09223-B018-416D-A0AC-523971B639F5}' = 'Fingerprint'
    '{8AF662BF-65A0-4D0A-A540-A338A999D36F}' = 'Facial recognition'
    '{27FBDB57-B613-4AF2-9D7E-4FA7A66C21AD}' = 'Trusted signal'
}
$eventMeaning = @{
    3520 = 'Unlock attempt initiated'
    5520 = 'Unlock policy NOT configured'
    6520 = 'Warning'
    7520 = 'Error'
    8520 = 'Success'
}

function Resolve-Guids([string]$raw) {
    if (-not $raw) { return '(not set)' }
    $names = foreach ($m in [regex]::Matches($raw, '\{[0-9A-Fa-f\-]+\}')) {
        $g = $m.Value.ToUpper()
        if ($providerNames.ContainsKey($g)) { $providerNames[$g] } else { $g }
    }
    if ($names) { $names -join ', ' } else { $raw }
}

# DeviceUnlock policy (best-effort read across the PassportForWork tree)
$first = $null; $second = $null; $plugin = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            foreach ($p in $v.PSObject.Properties) {
                if ($p.Name -match 'FirstUnlock')  { $first  = $p.Value }
                if ($p.Name -match 'SecondUnlock') { $second = $p.Value }
                if ($p.Name -match 'DeviceUnlock|PluginList') { $plugin = $p.Value }
            }
        }
    }
}

Write-Host ''
Write-Host '  WHfB Multifactor Device Unlock - Config' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  First unlock factors  : {0}' -f (Resolve-Guids ([string]$first)))
Write-Host ('  Second unlock factors : {0}' -f (Resolve-Guids ([string]$second)))
if ($plugin) { Write-Host ('  DeviceUnlock plugin   : {0}' -f (Resolve-Guids ([string]$plugin))) }
if (-not ($first -or $second -or $plugin)) {
    Write-Host '  No DeviceUnlock policy found in the registry (feature not configured here).' -ForegroundColor Gray
}
Write-Host ''
Write-Host '  Recent Device Unlock events:' -ForegroundColor Cyan
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-HelloForBusiness/Operational' } -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $eventMeaning.ContainsKey($_.Id) } | Select-Object -First $MaxEvents
    if ($evts) {
        $evts | ForEach-Object {
            Write-Host ('    {0}  [{1}] {2}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.Id, $eventMeaning[$_.Id])
        }
    } else {
        Write-Host '    No Device Unlock events found (feature not in use on this device).' -ForegroundColor Gray
    }
} catch {
    Write-Host '    HelloForBusiness/Operational log not available on this device.' -ForegroundColor Gray
}
Write-Host ''
