<#
.SYNOPSIS
    Read-only reader that pulls recent Windows Hello for Business events from all
    three relevant logs and maps the known IDs to plain-English meanings.

.DESCRIPTION
    Changes nothing. Reads:
      - Microsoft-Windows-User Device Registration/Admin  (provisioning: 358/360/362/363)
      - Microsoft-Windows-HelloForBusiness/Operational     (device unlock: 3520-8520)
      - Microsoft-Windows-AAD/Operational                  (token / PRT activity)
    and prints one merged, time-sorted timeline with a friendly label for each
    known event ID. Empty logs are reported gracefully (normal on a healthy box).

.PARAMETER MaxPerLog
    Max events to read per log. Default 30.

.EXAMPLE
    .\Get-WHfBEventReport.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-event-id-catalog.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param([int]$MaxPerLog = 30)

$meaning = @{
    358 = 'Provisioning will be launched'
    360 = 'Provisioning will NOT be launched (prereq failed)'
    362 = 'Blocked - device/STS authentication did not succeed'
    363 = 'Microsoft Passport (NGC) key missing'
    3520 = 'Device Unlock: attempt initiated'
    5520 = 'Device Unlock: policy not configured'
    6520 = 'Device Unlock: warning'
    7520 = 'Device Unlock: error'
    8520 = 'Device Unlock: success'
}
$logs = @(
    'Microsoft-Windows-User Device Registration/Admin',
    'Microsoft-Windows-HelloForBusiness/Operational',
    'Microsoft-Windows-AAD/Operational'
)

$rows = New-Object System.Collections.Generic.List[object]
foreach ($log in $logs) {
    $logShort = (($log -split '/')[0]).Replace('Microsoft-Windows-','')
    try {
        Get-WinEvent -LogName $log -MaxEvents $MaxPerLog -ErrorAction Stop | ForEach-Object {
            $firstLine = ($_.Message -split "`n")[0]
            $label = if ($meaning.ContainsKey([int]$_.Id)) { $meaning[[int]$_.Id] } else { $firstLine }
            $rows.Add([PSCustomObject]@{
                Time    = $_.TimeCreated
                Log     = $logShort
                Id      = $_.Id
                Level   = $_.LevelDisplayName
                Meaning = $label
            })
        }
    } catch {
        Write-Host ('  ({0}: no events / not present)' -f $logShort) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host '  WHfB Event Timeline (newest first)' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
if ($rows.Count) {
    $rows | Sort-Object Time -Descending | Select-Object -First 40 |
        Format-Table @{n='Time';e={$_.Time.ToString('MM-dd HH:mm')}}, Log, Id, Level, Meaning -AutoSize
} else {
    Write-Host '  No WHfB events found in any of the three logs on this device.' -ForegroundColor Gray
}
Write-Host ''
