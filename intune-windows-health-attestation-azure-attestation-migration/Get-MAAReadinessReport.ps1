<#
.SYNOPSIS
    Identifies Intune compliance policies that use health attestation and tests MAA endpoint reachability.

.DESCRIPTION
    Read-only audit script for the MAA migration (H1 2027). Queries all Windows compliance policies
    via the Microsoft Graph API and reports which policies have BitLocker, Secure Boot, or Code
    Integrity health attestation settings enabled. Also identifies the device groups assigned to
    each affected policy and tests TCP/443 connectivity to all MAA endpoints from the current
    execution context.

    Run this script as SYSTEM (via a scheduled task) to test the network path that the
    HealthAttestation service actually uses. Running as a regular user tests a different proxy
    configuration and may return a false-positive healthy result.

    Uses app-only authentication (certificate) for unattended runs or -UseDeviceCode for
    interactive testing. Requires the Microsoft Graph PowerShell SDK module.

    No changes are made to any policy, device, or tenant configuration.

.PARAMETER TenantId
    The Entra ID tenant ID (GUID) for app-only authentication.

.PARAMETER ClientId
    The app registration client ID for app-only authentication.

.PARAMETER CertificateThumbprint
    The certificate thumbprint for app-only authentication.

.PARAMETER UseDeviceCode
    Switch. Use interactive device code authentication instead of app-only cert auth.

.PARAMETER ExportCsv
    Switch. Export the results to a CSV file in the current directory.

.PARAMETER CsvPath
    Optional. Full path for the CSV export. Defaults to Get-MAAReadinessReport_YYYYMMDD.csv
    in the current directory.

.EXAMPLE
    # Interactive authentication - lists affected policies and tests connectivity
    .\Get-MAAReadinessReport.ps1 -UseDeviceCode

.EXAMPLE
    # App-only authentication with CSV export
    .\Get-MAAReadinessReport.ps1 -TenantId "your-tenant-id" -ClientId "your-app-id" `
        -CertificateThumbprint "ABCDEF..." -ExportCsv

.NOTES
    Blog:       https://endpointweekly.com/blog/intune-windows-health-attestation-azure-attestation-migration.html
    Repo:       https://github.com/Imran76Awan/Daily-Tasks/tree/main/intune-windows-health-attestation-azure-attestation-migration
    Required:   Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement modules
    Scope:      DeviceManagementConfiguration.Read.All, Group.Read.All
    Auth:       App-only (cert) or interactive device code
#>

[CmdletBinding(DefaultParameterSetName = 'DeviceCode')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [switch]$ExportCsv,

    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:hadError = $false

# --- MAA endpoints to test ---------------------------------------------------
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

# --- Connectivity test -------------------------------------------------------
Write-Host "[1/3] Testing MAA endpoint reachability (TCP 443)..." -ForegroundColor Cyan
$ConnResults = foreach ($ep in $MAAEndpoints) {
    $result = Test-NetConnection -ComputerName $ep -Port 443 -InformationLevel Quiet `
        -WarningAction SilentlyContinue 2>$null
    [PSCustomObject]@{
        Endpoint         = $ep
        TcpPort443       = if ($result) { 'Reachable' } else { 'BLOCKED' }
        Status           = if ($result) { 'OK' } else { 'FAIL' }
    }
}

Write-Host ''
Write-Host 'MAA Endpoint Connectivity (from current execution context):' -ForegroundColor White
$ConnResults | Format-Table -AutoSize

$blockedCount = ($ConnResults | Where-Object Status -eq 'FAIL').Count
if ($blockedCount -gt 0) {
    Write-Warning "$blockedCount MAA endpoint(s) are unreachable from this context. If running as a regular user, re-run via a SYSTEM-context scheduled task for an authoritative result."
    $script:hadError = $true
}

# --- Graph authentication ----------------------------------------------------
Write-Host "[2/3] Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','Group.Read.All' `
            -UseDeviceAuthentication -NoWelcome
    }
} catch {
    Write-Error "Graph connection failed: $_"
    exit 1
}

# --- Query compliance policies -----------------------------------------------
Write-Host "[3/3] Querying compliance policies for health attestation settings..." -ForegroundColor Cyan
try {
    $allPolicies = Invoke-MgGraphRequest -Method GET `
        '/beta/deviceManagement/deviceCompliancePolicies' -OutputType PSObject

    $windows10Type = '#microsoft.graph.windows10CompliancePolicy'
    $affectedPolicies = $allPolicies.value | Where-Object {
        $_.'@odata.type' -eq $windows10Type -and (
            $_.bitLockerEnabled -eq $true -or
            $_.secureBootEnabled -eq $true -or
            $_.codeIntegrityEnabled -eq $true
        )
    }
} catch {
    Write-Error "Failed to query compliance policies: $_"
    Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Host ''
if ($affectedPolicies.Count -eq 0) {
    Write-Host 'No Windows 10/11 compliance policies with health attestation settings found.' -ForegroundColor Green
    Write-Host 'This tenant has no BitLocker, Secure Boot, or Code Integrity compliance settings.' -ForegroundColor Green
    Disconnect-MgGraph | Out-Null
    exit 0
}

Write-Host "Found $($affectedPolicies.Count) affected compliance policy/policies:" -ForegroundColor Yellow

$report = foreach ($policy in $affectedPolicies) {
    # Get assigned groups for this policy
    $assignments = @()
    try {
        $assignmentResponse = Invoke-MgGraphRequest -Method GET `
            "/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" -OutputType PSObject
        foreach ($a in $assignmentResponse.value) {
            if ($a.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $groupId = $a.target.groupId
                try {
                    $group = Invoke-MgGraphRequest -Method GET "/v1.0/groups/$groupId" -OutputType PSObject
                    $assignments += $group.displayName
                } catch {
                    $assignments += "Group:$groupId"
                }
            } elseif ($a.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $assignments += 'All Devices'
            } elseif ($a.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $assignments += 'All Users'
            }
        }
    } catch {
        $assignments += 'Unable to retrieve assignments'
        $script:hadError = $true
    }

    [PSCustomObject]@{
        PolicyName           = $policy.displayName
        BitLockerEnabled     = $policy.bitLockerEnabled
        SecureBootEnabled    = $policy.secureBootEnabled
        CodeIntegrityEnabled = $policy.codeIntegrityEnabled
        AssignedTo           = ($assignments -join '; ')
        PolicyId             = $policy.id
    }
}

$report | Format-Table -AutoSize

Write-Host ''
Write-Host '--- Summary ---' -ForegroundColor Cyan
Write-Host "Affected policies:     $($affectedPolicies.Count)"
Write-Host "MAA endpoints blocked: $blockedCount / $($MAAEndpoints.Count)"

if ($blockedCount -gt 0) {
    Write-Host ''
    Write-Host 'ACTION REQUIRED: MAA endpoints are blocked. Devices with the policies above' -ForegroundColor Red
    Write-Host 'will become noncompliant after the H1 2027 Intune MAA migration.' -ForegroundColor Red
    Write-Host 'Add *.attest.azure.net to your firewall allowlist and exclude from SSL inspection.' -ForegroundColor Red
} else {
    Write-Host ''
    Write-Host 'MAA endpoints are reachable from this context. Verify from SYSTEM context' -ForegroundColor Green
    Write-Host 'to confirm the HealthAttestation service will also have access.' -ForegroundColor Green
}

if ($ExportCsv) {
    if (-not $CsvPath) {
        $CsvPath = "Get-MAAReadinessReport_$(Get-Date -Format 'yyyyMMdd').csv"
    }
    $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Report exported to: $CsvPath" -ForegroundColor Cyan
}

Disconnect-MgGraph | Out-Null

exit $(if ($script:hadError) { 1 } else { 0 })
