<#
.SYNOPSIS
    Read-only report of whether a device provisioned Windows Hello for Business
    (e.g. during Autopilot/OOBE) and the settings that control it.

.DESCRIPTION
    Changes nothing. Reports join type (AzureAdJoined / DomainJoined), NgcSet,
    the UsePassportForWork policy and DisablePostLogonProvisioning, so you can see
    whether Hello provisioned at first sign-in and whether auto-provisioning is
    deferred. Also surfaces the most recent User Device Registration events.

.PARAMETER MaxEvents
    Number of recent User Device Registration events to show. Default 10.

.EXAMPLE
    .\Get-WHfBProvisioningState.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-autopilot-esp-provisioning.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param([int]$MaxEvents = 10)

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

$usePassport = $null; $disablePostLogon = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.UsePassportForWork)          { $usePassport      = $v.UsePassportForWork }
            if ($null -ne $v.DisablePostLogonProvisioning) { $disablePostLogon = $v.DisablePostLogonProvisioning }
        }
    }
}

$joinType =
    if ($ds['AzureAdJoined'] -eq 'YES' -and $ds['DomainJoined'] -eq 'YES') { 'Entra hybrid joined' }
    elseif ($ds['AzureAdJoined'] -eq 'YES') { 'Entra joined' }
    elseif ($ds['DomainJoined'] -eq 'YES') { 'Domain joined (on-prem)' }
    else { 'Workgroup / not joined' }

Write-Host ''
Write-Host '  WHfB Provisioning State (Autopilot / OOBE)' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Join type                     : {0}' -f $joinType)
Write-Host ('  NgcSet (Hello provisioned)    : {0}' -f $ds['NgcSet'])
Write-Host ('  UsePassportForWork policy     : {0}' -f $(if ($null -ne $usePassport) { $usePassport } else { 'not set (default = enabled on Entra joined)' }))
Write-Host ('  DisablePostLogonProvisioning  : {0}' -f $(if ($null -ne $disablePostLogon) { $disablePostLogon } else { 'not set' }))
Write-Host '  ------------------------------------------------------------'
if ($joinType -eq 'Entra hybrid joined' -and $ds['NgcSet'] -ne 'YES') {
    Write-Host '  Hybrid device without a Hello credential - if provisioning failed at OOBE,' -ForegroundColor Yellow
    Write-Host '  check DC line-of-sight / trust model (cloud Kerberos trust avoids this).' -ForegroundColor Yellow
} else {
    Write-Host '  State read successfully.' -ForegroundColor Green
}

Write-Host ''
Write-Host '  Recent User Device Registration events:' -ForegroundColor Cyan
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-User Device Registration/Admin' } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object { Write-Host ('    {0}  [{1}] {2}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.Id, ($_.Message -split "`n")[0]) }
} catch {
    Write-Host '    No User Device Registration events available.' -ForegroundColor Gray
}
Write-Host ''
