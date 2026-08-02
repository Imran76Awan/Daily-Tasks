<#
.SYNOPSIS
    Read-only detection for a broken Windows Hello for Business (NGC) credential.

.DESCRIPTION
    Checks, without changing anything, whether the two NGC services are running and whether
    dsregcmd reports a provisioned Hello credential (NgcSet). Intended as the Detection script
    half of an Intune Proactive Remediation pair (paired with Remediate-NgcContainerHealth.ps1).

    This never touches the Ngc folder, never clears a TPM, and never deletes any credential.
    It exits 1 only when there is genuine evidence Hello is broken, so the Remediation script
    can then run the SUPPORTED per-user reset (certutil -deletehellocontainer) instead of
    anyone reaching for the folder-delete method.

    Exit codes (Proactive Remediation convention):
      0 = healthy, no remediation needed
      1 = an NGC service is not running, or dsregcmd shows no Hello credential present

.NOTES
    Blog: https://endpointweekly.com/blog/whfb-ngc-container-explained.html
    Pairs with: Remediate-NgcContainerHealth.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Detect-NgcContainerHealth.ps1
#>

$ErrorActionPreference = 'Stop'

try {
    $services = Get-Service -Name NgcSvc, NgcCtnrSvc -ErrorAction Stop
    $stopped = $services | Where-Object { $_.Status -ne 'Running' }

    $dsregOutput = & dsregcmd /status 2>&1
    $ngcSetLine = $dsregOutput | Select-String -Pattern 'NgcSet\s*:\s*(\S+)'
    $ngcSet = if ($ngcSetLine) { ($ngcSetLine.Matches[0].Groups[1].Value) } else { 'UNKNOWN' }

    if ($stopped) {
        Write-Output "NOT HEALTHY: service(s) not running - $($stopped.Name -join ', ')"
        exit 1
    }

    if ($ngcSet -eq 'NO') {
        Write-Output "NOT HEALTHY: dsregcmd reports NgcSet: NO (no Hello credential provisioned)"
        exit 1
    }

    if ($ngcSet -eq 'UNKNOWN') {
        Write-Output "NOT HEALTHY: could not read NgcSet from dsregcmd output"
        exit 1
    }

    Write-Output "HEALTHY: NgcSvc and NgcCtnrSvc running, NgcSet: $ngcSet"
    exit 0
}
catch {
    Write-Output "DETECTION ERROR: $($_.Exception.Message)"
    exit 1
}
