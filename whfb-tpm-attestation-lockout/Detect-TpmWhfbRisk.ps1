<#
.SYNOPSIS
    Intune Proactive Remediation - DETECTION script for TPM/WHfB hardware-backing risk.

.DESCRIPTION
    Read-only. Exits 1 (non-compliant, triggers the remediation script) if either of
    these is true, and exits 0 (compliant) otherwise:

      1. TPM is present and LOCKED OUT (blocks PIN entry right now).
      2. TPM is present and ready, but the RequireSecurityDevice WHfB policy is not
         enforced - meaning Windows Hello could be running on a software key with
         no hardware guarantee, and nothing in the Intune portal would show it.

    This script does not change anything and does not attempt to fix either
    condition - see Repair-TpmWhfbRiskReport.ps1 for what runs on detection.

.NOTES
    Author      : Imran Awan (EndpointWeekly)
    Blog        : https://endpointweekly.com/blog/whfb-tpm-attestation-lockout.html
    Deploy as   : Intune Proactive Remediation - Detection script
    Run context : Logged-on user (required so NgcSet reads correctly; TPM checks
                  work in either context)
    Exit codes  : 0 = compliant, no remediation needed
                  1 = non-compliant, remediation script will run (report only, see below)
#>

$issues = New-Object System.Collections.Generic.List[string]

# --- TPM state ---
$tpm = $null
try { $tpm = Get-Tpm -ErrorAction Stop } catch { }

if ($tpm -and $tpm.TpmPresent -and $tpm.LockedOut) {
    $issues.Add("TPM is LOCKED OUT (LockoutCount=$($tpm.LockoutCount)) - PIN/Hello sign-in is blocked.")
}

# --- RequireSecurityDevice policy enforcement ---
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

if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady -and $requireSecDevice -ne 1) {
    $issues.Add("TPM is healthy but RequireSecurityDevice is NOT enforced - WHfB could be running on a software key with no hardware guarantee.")
}

if ($issues.Count -gt 0) {
    $issues | ForEach-Object { Write-Output $_ }
    exit 1
} else {
    Write-Output "Compliant: TPM healthy (or absent) and hardware-backing policy enforced where applicable."
    exit 0
}
