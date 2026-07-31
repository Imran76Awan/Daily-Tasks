<#
.SYNOPSIS
    Read-only health check for Windows Hello for Business on-premises single
    sign-on (SSO): walks the PRT -> partial TGT -> full TGT chain and names the
    first broken link.

.DESCRIPTION
    Changes nothing. Reads dsregcmd (AzureAdPrt / OnPremTgt / CloudTgt / join
    state) and klist (is a krbtgt ticket cached?), then reports which link in the
    passwordless-to-Kerberos chain is missing when on-prem resources prompt for
    credentials even though sign-in and cloud apps work.

.EXAMPLE
    .\Test-OnPremSsoHealth.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-onprem-sso-troubleshooting.html
    Safe   : READ-ONLY.
    Run as : The affected signed-in user, on their normal network.
#>

[CmdletBinding()]
param()

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

$prt      = $ds['AzureAdPrt']
$onPrem   = $ds['OnPremTgt']
$domain   = $ds['DomainJoined']
$aad      = $ds['AzureAdJoined']

$klist = & klist 2>$null
$hasTgt = ($klist | Select-String -Pattern 'krbtgt/' -Quiet)

$link =
    if ($prt -ne 'YES')            { 'NO PRT - repair the Primary Refresh Token first; nothing on-prem works without it.' }
    elseif ($domain -ne 'YES')     { 'Device is not domain/hybrid joined - on-prem Kerberos SSO does not apply here.' }
    elseif ($onPrem -ne 'YES' -and -not $hasTgt) { 'PRT present but NO on-prem TGT - check DC line-of-sight, Entra Kerberos setup, and DC patch level.' }
    elseif ($onPrem -eq 'YES' -and $hasTgt)      { 'Chain healthy - PRT + full TGT present. A single-app prompt is likely an SPN/delegation issue, not WHfB.' }
    else                            { 'Partial state - see the values above; the on-prem TGT has not fully established.' }

Write-Host ''
Write-Host '  WHfB On-Prem SSO Health' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Join (AAD / Domain)   : {0} / {1}' -f $aad, $domain)
Write-Host ('  AzureAdPrt (PRT)      : {0}' -f $prt)
Write-Host ('  OnPremTgt (full TGT)  : {0}' -f $onPrem)
Write-Host ('  CloudTgt              : {0}' -f $ds['CloudTgt'])
Write-Host ('  krbtgt ticket cached  : {0}' -f $hasTgt)
Write-Host '  ------------------------------------------------------------'
$c = if ($link -like 'Chain healthy*') { 'Green' } elseif ($link -like 'Device is not*') { 'Gray' } else { 'Yellow' }
Write-Host ('  {0}' -f $link) -ForegroundColor $c
Write-Host ''
