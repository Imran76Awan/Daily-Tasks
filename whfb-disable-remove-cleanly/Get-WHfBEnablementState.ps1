<#
.SYNOPSIS
    Read-only report of whether Windows Hello for Business is enabled on this
    device and whether a credential still exists to clean up.

.DESCRIPTION
    Changes nothing. Reports the UsePassportForWork (CSP) and Enabled (GPO) policy
    values, the DisablePostLogonProvisioning setting, and NgcSet from dsregcmd.
    Use it to confirm a "disable WHfB" policy actually applied and to find devices
    that are disabled in policy but still carry a provisioned credential (which
    means an orphaned key you should clean up with certutil -deletehellocontainer).

.EXAMPLE
    .\Get-WHfBEnablementState.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-disable-remove-cleanly.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param()

$usePassport = $null; $disablePostLogon = $null; $gpoEnabled = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.UsePassportForWork)          { $usePassport      = $v.UsePassportForWork }
            if ($null -ne $v.DisablePostLogonProvisioning) { $disablePostLogon = $v.DisablePostLogonProvisioning }
            if ($null -ne $v.Enabled)                      { $gpoEnabled       = $v.Enabled }
        }
    }
}

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}
$ngcSet = $ds['NgcSet']

$enabled = ($usePassport -eq 1) -or ($gpoEnabled -eq 1)
$verdict =
    if ($enabled -and $ngcSet -eq 'YES')       { 'ENABLED and provisioned (credential present).' }
    elseif (-not $enabled -and $ngcSet -eq 'YES') { 'DISABLED in policy but a credential STILL EXISTS - clean up with certutil -deletehellocontainer.' }
    elseif (-not $enabled)                     { 'DISABLED and no credential provisioned - clean.' }
    else                                       { 'Enabled in policy, no credential yet (will provision at sign-in).' }

Write-Host ''
Write-Host '  WHfB Enablement State' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  UsePassportForWork (CSP)      : {0}' -f $(if ($null -ne $usePassport) { $usePassport } else { 'not set' }))
Write-Host ('  Enabled (GPO)                 : {0}' -f $(if ($null -ne $gpoEnabled) { $gpoEnabled } else { 'not set' }))
Write-Host ('  DisablePostLogonProvisioning  : {0}' -f $(if ($null -ne $disablePostLogon) { $disablePostLogon } else { 'not set' }))
Write-Host ('  NgcSet (credential present)   : {0}' -f $ngcSet)
Write-Host '  ------------------------------------------------------------'
$c = if ($verdict -like 'DISABLED but*' -or $verdict -like 'DISABLED in policy*') { 'Yellow' } elseif ($verdict -like 'DISABLED and*') { 'Green' } else { 'Gray' }
Write-Host ('  {0}' -f $verdict) -ForegroundColor $c
Write-Host ''
