<#
.SYNOPSIS
    Supported remediation for a broken Windows Hello for Business (NGC) credential.

.DESCRIPTION
    Runs only after Detect-NgcContainerHealth.ps1 has found a problem. Performs exactly the
    two supported fixes from the companion blog post's "The fix" section, in order, and NOTHING
    else - it never deletes or takes ownership of the Ngc folder, and never clears a TPM.

    Step 1 - if either NGC service is stopped, start it (safe, reversible, supported).
    Step 2 - if the signed-in user still has no Hello credential (NgcSet: NO) after step 1,
             run the supported per-user reset: certutil -deletehellocontainer. This removes
             ONLY the signed-in user's broken credential and lets Windows re-provision cleanly
             on next sign-in. It is scoped to one user and does not touch other profiles.

    Run this as a Proactive Remediation "Remediation script" using the LOGGED-ON USER'S
    credentials (not SYSTEM) - certutil -deletehellocontainer run elevated/as SYSTEM deletes
    the wrong container and looks like a silent no-op.

    Exit codes:
      0 = remediation actions completed
      1 = remediation could not complete (see output)

.NOTES
    Blog: https://endpointweekly.com/blog/whfb-ngc-container-explained.html
    Pairs with: Detect-NgcContainerHealth.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediate-NgcContainerHealth.ps1
#>

$ErrorActionPreference = 'Stop'

try {
    $services = Get-Service -Name NgcSvc, NgcCtnrSvc -ErrorAction Stop
    foreach ($svc in $services) {
        if ($svc.Status -ne 'Running') {
            Write-Output "Starting stopped service: $($svc.Name)"
            Start-Service -Name $svc.Name
        }
    }

    Start-Sleep -Seconds 3

    $dsregOutput = & dsregcmd /status 2>&1
    $ngcSetLine = $dsregOutput | Select-String -Pattern 'NgcSet\s*:\s*(\S+)'
    $ngcSet = if ($ngcSetLine) { ($ngcSetLine.Matches[0].Groups[1].Value) } else { 'UNKNOWN' }

    if ($ngcSet -eq 'YES') {
        Write-Output "Remediated: services started, Hello credential now present (NgcSet: YES)"
        exit 0
    }

    Write-Output "Services running but no Hello credential yet - running the supported per-user reset"
    $certutilOutput = & certutil.exe -deletehellocontainer 2>&1
    Write-Output $certutilOutput

    Write-Output "Remediation actions complete. The user will be prompted to re-provision Hello on next sign-in."
    exit 0
}
catch {
    Write-Output "REMEDIATION ERROR: $($_.Exception.Message)"
    exit 1
}
