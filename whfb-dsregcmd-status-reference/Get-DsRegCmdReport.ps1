<#
.SYNOPSIS
    Read-only, structured reader for 'dsregcmd /status' focused on the Windows
    Hello for Business, join, PRT and Kerberos-ticket fields.

.DESCRIPTION
    Changes nothing. Parses dsregcmd /status into a hashtable, derives the join
    type from the AzureAdJoined/EnterpriseJoined/DomainJoined truth table, and
    prints the fields that matter for WHfB troubleshooting with plain-English
    verdicts. Optionally returns the full parsed object with -AsObject.

.PARAMETER AsObject
    Return the parsed dsregcmd fields as a PSCustomObject instead of the report.

.EXAMPLE
    .\Get-DsRegCmdReport.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-dsregcmd-status-reference.html
    Safe   : READ-ONLY.
    Run as : The signed-in user (NgcSet / AzureAdPrt / OnPremTgt need user context).
#>

[CmdletBinding()]
param([switch]$AsObject)

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_ ]+?)\s*:\s*(.+?)\s*$') { $ds[$Matches[1].Trim()] = $Matches[2].Trim() }
}

if ($AsObject) { return [PSCustomObject]$ds }

$joinType =
    if ($ds['AzureAdJoined'] -eq 'YES' -and $ds['DomainJoined'] -eq 'YES') { 'Microsoft Entra hybrid joined' }
    elseif ($ds['AzureAdJoined'] -eq 'YES') { 'Microsoft Entra joined' }
    elseif ($ds['EnterpriseJoined'] -eq 'YES') { 'On-premises DRS joined' }
    elseif ($ds['DomainJoined'] -eq 'YES') { 'Domain joined (on-prem only)' }
    else { 'Workgroup / not joined' }

Write-Host ''
Write-Host '  dsregcmd /status - WHfB Report' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Join type             : {0}' -f $joinType)
Write-Host ('  DeviceId              : {0}' -f $ds['DeviceId'])
Write-Host ('  TpmProtected          : {0}' -f $ds['TpmProtected'])
Write-Host ('  DeviceAuthStatus      : {0}' -f $ds['DeviceAuthStatus'])
Write-Host '  --- Windows Hello (User State) ---'
Write-Host ('  NgcSet                : {0}' -f $ds['NgcSet'])
Write-Host ('  CanReset              : {0}' -f $ds['CanReset'])
Write-Host '  --- SSO State ---'
Write-Host ('  AzureAdPrt            : {0}' -f $ds['AzureAdPrt'])
Write-Host ('  EnterprisePrt         : {0}' -f $ds['EnterprisePrt'])
Write-Host ('  OnPremTgt             : {0}' -f $ds['OnPremTgt'])
Write-Host ('  CloudTgt              : {0}' -f $ds['CloudTgt'])
Write-Host '  ------------------------------------------------------------'

$notes = New-Object System.Collections.Generic.List[string]
if ($ds['NgcSet'] -ne 'YES')        { $notes.Add('No Hello credential provisioned for this user (NgcSet != YES).') }
if ($ds['AzureAdPrt'] -ne 'YES')    { $notes.Add('No PRT - SSO and on-prem access will fail until this is fixed.') }
if ($ds['DomainJoined'] -eq 'YES' -and $ds['OnPremTgt'] -ne 'YES') { $notes.Add('Hybrid/domain device without an on-prem TGT - on-prem SSO will prompt.') }
if ($ds['TpmProtected'] -eq 'NO')   { $notes.Add('Device key is NOT TPM-protected (software key).') }

if ($notes.Count) {
    Write-Host '  Flags:' -ForegroundColor Yellow
    foreach ($n in $notes) { Write-Host ('    - {0}' -f $n) -ForegroundColor Yellow }
} else {
    Write-Host '  No issues flagged - Hello, PRT and TGT look healthy.' -ForegroundColor Green
}
Write-Host ''
