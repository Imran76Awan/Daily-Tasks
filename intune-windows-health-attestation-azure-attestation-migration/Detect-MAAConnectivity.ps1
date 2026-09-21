<#
.SYNOPSIS
    Intune Proactive Remediation DETECT script - tests MAA endpoint reachability from SYSTEM context.

.DESCRIPTION
    Tests TCP/443 connectivity to all Microsoft Azure Attestation (MAA) endpoints used by Intune
    for Windows 11 device health attestation (BitLocker, Secure Boot, Code Integrity compliance).

    Deploy as the Detection Script in an Intune Proactive Remediation pair. Run as: SYSTEM,
    64-bit PowerShell, with no user credentials required.

    Exit 0 = All tested MAA endpoints are reachable. Device is ready for the H1 2027 migration.
    Exit 1 = One or more MAA endpoints are blocked. Firewall or proxy remediation is required.

    This script is read-only. It tests network connectivity only and does not modify any
    device configuration, registry, or policy setting.

.NOTES
    Blog:   https://endpointweekly.com/blog/intune-windows-health-attestation-azure-attestation-migration.html
    Repo:   https://github.com/Imran76Awan/Daily-Tasks/tree/main/intune-windows-health-attestation-azure-attestation-migration
    Deploy: Intune > Devices > Scripts and remediations > Proactive remediations
            Run as: SYSTEM | 64-bit | No user context required
#>

$ErrorActionPreference = 'Stop'

$MAAEndpoints = @(
    'intunemaape1.attest.azure.net',
    'intunemaape2.attest.azure.net',
    'intunemaape3.attest.azure.net',
    'intunemaape4.attest.azure.net',
    'intunemaape5.attest.azure.net',
    'intunemaape6.attest.azure.net',
    'intunemaape7.attest.azure.net',
    'intunemaape8.attest.azure.net',
    'intunemaape9.attest.azure.net'
)

try {
    $blocked = @()
    foreach ($ep in $MAAEndpoints) {
        $ok = Test-NetConnection -ComputerName $ep -Port 443 -InformationLevel Quiet `
            -WarningAction SilentlyContinue 2>$null
        if (-not $ok) { $blocked += $ep }
    }

    if ($blocked.Count -eq 0) {
        Write-Output "MAA endpoints reachable: all $($MAAEndpoints.Count) endpoints pass TCP/443. Device is ready for MAA migration."
        exit 0
    } else {
        Write-Output "MAA endpoints BLOCKED: $($blocked.Count) endpoint(s) unreachable from SYSTEM context: $($blocked -join ', '). Firewall/proxy remediation required before H1 2027 migration."
        exit 1
    }
} catch {
    Write-Output "Detection script error: $_"
    exit 1
}
