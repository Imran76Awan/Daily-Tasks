<#
.SYNOPSIS
    Checks TPM dictionary-attack lockout status and, only if explicitly asked to,
    resets the TPM lockout counter that can silently block WHfB key creation.

.DESCRIPTION
    After repeated failed PIN attempts or TPM operations, the TPM enters a lockout
    state with an exponentially increasing cooldown. While locked out, WHfB key
    creation fails silently — the user sees no clear error. This is reported as
    Event ID 1026 (source TPM-WMI) in the System log: "TPM hardware cannot be
    provisioned automatically."

    By default this script only REPORTS the lockout status — it changes nothing.
    Pass -Force to actually reset the lockout counter via Reset-TpmLockout.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/whfb-provisioning-failure-fix.html
    Requires:    Run as Administrator
    Version:     1.0
    Date:        2026-07-23

.PARAMETER Force
    Actually reset the TPM lockout counter. Without this switch, the script only
    reports status and makes no changes.

.EXAMPLE
    .\Reset-WHfBTpmLockout.ps1
    Reports TPM lockout status only. Makes no changes.

.EXAMPLE
    .\Reset-WHfBTpmLockout.ps1 -Force
    Reports status, then resets the TPM lockout counter if the TPM is owned by the OS.
#>

[CmdletBinding()]
param(
    [switch]$Force
)

Write-Host "`n=== TPM Lockout Check ===" -ForegroundColor Cyan

$tpm = Get-Tpm
Write-Host "TPM Present:        $($tpm.TpmPresent)"
Write-Host "TPM Owned:          $($tpm.TpmOwned)"
Write-Host "Lockout Count:      $($tpm.LockoutCount)"
Write-Host "Lockout HealTime:   $($tpm.LockoutHealTime)"

if ($tpm.LockoutCount -eq 0) {
    Write-Host "`nNo lockout detected — nothing to reset." -ForegroundColor Green
    return
}

Write-Host "`nWARNING: This device has $($tpm.LockoutCount) recorded TPM lockout attempt(s)." -ForegroundColor Yellow
Write-Host "This means WHfB key creation (and possibly other TPM operations) may fail silently until the cooldown clears or the counter is reset." -ForegroundColor Yellow

Write-Host "`nIMPORTANT — read before using -Force:" -ForegroundColor Red
Write-Host "  Resetting the lockout counter does NOT clear the TPM itself and is safe on its own." -ForegroundColor Red
Write-Host "  But do not confuse this with clearing the TPM (tpm.msc > Clear TPM, or BIOS 'Clear TPM')." -ForegroundColor Red
Write-Host "  Clearing the TPM destroys every key it protects, including BitLocker volume keys." -ForegroundColor Red
Write-Host "  If BitLocker is enabled, confirm the recovery key is escrowed to Entra ID or Active Directory" -ForegroundColor Red
Write-Host "  BEFORE touching the TPM any further than this lockout-counter reset." -ForegroundColor Red

if (-not $Force) {
    Write-Host "`nNo changes made. Re-run with -Force to reset the lockout counter." -ForegroundColor Cyan
    return
}

if (-not $tpm.TpmOwned) {
    Write-Host "`nTPM is not owned by the OS — lockout reset is not available from Windows." -ForegroundColor Red
    Write-Host "This requires BIOS/UEFI-level TPM intervention instead." -ForegroundColor Red
    return
}

Write-Host "`nResetting TPM lockout counter..." -ForegroundColor Cyan
Reset-TpmLockout
Write-Host "TPM lockout counter reset. Re-run Get-WHfBProvisioningDiagnostics.ps1 to confirm." -ForegroundColor Green
