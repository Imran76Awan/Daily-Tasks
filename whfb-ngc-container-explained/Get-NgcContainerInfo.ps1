<#
.SYNOPSIS
    Read-only triage of the Windows Hello for Business (NGC) container on this device.

.DESCRIPTION
    Changes nothing and never touches the container contents. It reports the four
    things you should check BEFORE anyone suggests "just delete the Ngc folder":

      1. Whether the NGC container path exists.
      2. The state of the two NGC services (NgcSvc, NgcCtnrSvc) - both must run.
      3. NgcSet / NgcKeyId from dsregcmd (is a Hello credential present?).
      4. TPM presence/readiness (a bad TPM breaks Hello for everyone).

    It deliberately does NOT read the key material inside the container (it can't;
    the store is protected) and does NOT delete anything. The supported reset is
    'certutil.exe -deletehellocontainer' run in the affected user's context.

.EXAMPLE
    .\Get-NgcContainerInfo.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-ngc-container-explained.html
    Safe   : READ-ONLY. Does not delete, re-own or modify the Ngc folder.
#>

[CmdletBinding()]
param()

$ngcPath = 'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'

# 1. Container path
$exists = Test-Path $ngcPath
$childCount = $null
if ($exists) {
    try { $childCount = @(Get-ChildItem -LiteralPath $ngcPath -Force -ErrorAction Stop).Count }
    catch { $childCount = 'access denied (expected - folder is protected)' }
}

# 2. Services
$svc = Get-Service NgcSvc, NgcCtnrSvc -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, Status

# 3. dsregcmd NgcSet / NgcKeyId
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

# 4. TPM
$tpm = $null
try { $tpm = Get-Tpm -ErrorAction Stop } catch { }

Write-Host ''
Write-Host '  NGC (Windows Hello) Container - Triage' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Container path exists : {0}' -f $exists)
Write-Host ('  Container entries     : {0}' -f $childCount)
Write-Host '  NGC services:'
foreach ($s in $svc) {
    $c = if ($s.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host ('    {0,-11} {1,-30} {2}' -f $s.Name, $s.DisplayName, $s.Status) -ForegroundColor $c
}
Write-Host ('  NgcSet                : {0}' -f $ds['NgcSet'])
Write-Host ('  NgcKeyId              : {0}' -f $ds['NgcKeyId'])
if ($tpm) {
    Write-Host ('  TPM present / ready   : {0} / {1}' -f $tpm.TpmPresent, $tpm.TpmReady)
} else {
    Write-Host '  TPM present / ready   : (Get-Tpm unavailable)'
}
Write-Host '  ------------------------------------------------------------'
$stopped = @($svc | Where-Object Status -ne 'Running')
if ($stopped.Count) {
    Write-Host '  ACTION: an NGC service is not running - START IT, do not delete the folder.' -ForegroundColor Yellow
} elseif ($ds['NgcSet'] -ne 'YES') {
    Write-Host '  NOTE: no Hello credential set for this user. Re-provision via sign-in;' -ForegroundColor Gray
    Write-Host '        to reset a broken one use: certutil.exe -deletehellocontainer (as the user).' -ForegroundColor Gray
} else {
    Write-Host '  Hello credential present and services healthy.' -ForegroundColor Green
}
Write-Host ''
