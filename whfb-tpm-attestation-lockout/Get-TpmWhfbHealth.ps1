<#
.SYNOPSIS
    Read-only TPM health check for Windows Hello for Business - is the TPM present,
    ready, and not locked out, and is the Hello key likely hardware-backed?

.DESCRIPTION
    Changes nothing. Reports Get-Tpm state (present / ready / lockout / version /
    manufacturer), the RequireSecurityDevice policy value, and NgcSet. Flags the
    two risky states: a locked-out TPM (which blocks PIN entry until it self-heals)
    and a device with no usable TPM where WHfB may have provisioned a SOFTWARE key.

.EXAMPLE
    .\Get-TpmWhfbHealth.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-tpm-attestation-lockout.html
    Safe   : READ-ONLY. Does not clear or reset the TPM.
#>

[CmdletBinding()]
param()

$tpm = $null
try { $tpm = Get-Tpm -ErrorAction Stop } catch { }

$requireSecDevice = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.RequireSecurityDevice) { $requireSecDevice = $v.RequireSecurityDevice }
        }
    }
}

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

Write-Host ''
Write-Host '  TPM + WHfB Health' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
if ($tpm) {
    Write-Host ('  TpmPresent            : {0}' -f $tpm.TpmPresent)
    Write-Host ('  TpmReady              : {0}' -f $tpm.TpmReady)
    Write-Host ('  LockedOut             : {0}' -f $tpm.LockedOut)
    Write-Host ('  LockoutCount          : {0}' -f $tpm.LockoutCount)
    Write-Host ('  ManufacturerVersion   : {0}' -f $tpm.ManufacturerVersion)
} else {
    Write-Host '  Get-Tpm unavailable (no TPM cmdlet / no TPM present).' -ForegroundColor Yellow
}
Write-Host ('  RequireSecurityDevice : {0}' -f $(if ($null -ne $requireSecDevice) { $requireSecDevice } else { 'not set (software fallback possible)' }))
Write-Host ('  NgcSet (Hello present): {0}' -f $ds['NgcSet'])
Write-Host '  ------------------------------------------------------------'
if ($tpm -and $tpm.LockedOut) {
    Write-Host '  TPM IS LOCKED OUT - PIN/Hello operations are blocked. Usually self-heals;' -ForegroundColor Red
    Write-Host '  wait for the lockout to clear rather than clearing the TPM (which wipes keys).' -ForegroundColor Red
} elseif ((-not $tpm -or -not $tpm.TpmPresent -or -not $tpm.TpmReady) -and $ds['NgcSet'] -eq 'YES' -and $requireSecDevice -ne 1) {
    Write-Host '  WARNING: no usable TPM but a Hello credential exists and RequireSecurityDevice' -ForegroundColor Yellow
    Write-Host '  is not enforced - this credential may be a SOFTWARE key (no hardware guarantee).' -ForegroundColor Yellow
} elseif ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
    Write-Host '  TPM present, ready and not locked out - Hello can be hardware-backed.' -ForegroundColor Green
} else {
    Write-Host '  State captured.' -ForegroundColor Gray
}
Write-Host ''
