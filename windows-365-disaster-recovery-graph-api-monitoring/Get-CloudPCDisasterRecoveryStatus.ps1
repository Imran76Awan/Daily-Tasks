<#
.SYNOPSIS
    Reports every Windows 365 Cloud PC currently in a disaster recovery
    failover, failback, or running from its DR region, via Microsoft Graph.

.DESCRIPTION
    Microsoft's September 2026 Graph update added the "isDisasterRecoveryActive"
    property and two new "status" enum values ("failoverInProgress" and
    "failbackInProgress") to the cloudPC beta resource. This script queries
    every Cloud PC in the tenant, applies the "Prefer: include-unknown-enum-members"
    header required to see the new status values, and reports anything
    currently affected by a disaster recovery event.

    Read-only. Issues Graph GET requests only - makes no changes to any
    Cloud PC, license, or policy.

.PARAMETER CsvPath
    Optional path to export the full result set as CSV.

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-365-disaster-recovery-graph-api-monitoring.html

    Requires the Microsoft.Graph.Beta.DeviceManagement.Administration module
    and the CloudPC.Read.All permission (delegated or application).

    This uses the /beta Graph endpoint because this feature is not yet in
    the stable v1.0 API. Beta APIs are subject to change without notice -
    re-verify the property/status names against Microsoft Learn before
    relying on this in a long-running automation.

    Exit 0 = No Cloud PCs currently affected by a disaster recovery event
    Exit 1 = One or more Cloud PCs currently in failover, failback, or
             running from their DR region
    Exit 2 = Script error (for example, could not connect to Graph)

.EXAMPLE
    .\Get-CloudPCDisasterRecoveryStatus.ps1
    Connect interactively and print a summary of any Cloud PCs currently
    affected by disaster recovery.

.EXAMPLE
    .\Get-CloudPCDisasterRecoveryStatus.ps1 -CsvPath "C:\Temp\cloudpc-dr-status.csv"
    Same check, also exporting the full per-device result set to CSV for a
    scheduled run or a dashboard.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

try {
    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "CloudPC.Read.All" -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Host "ERROR: could not connect to Microsoft Graph: $_"
    exit 2
}

try {
    $uri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs" +
           "?`$select=id,displayName,status,isDisasterRecoveryActive,disasterRecoveryCapability"

    $headers = @{ "Prefer" = "include-unknown-enum-members" }

    $results = New-Object System.Collections.Generic.List[object]
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -Headers $headers -ErrorAction Stop

    while ($true) {
        foreach ($cpc in $response.value) {
            $cap = $cpc.disasterRecoveryCapability
            $results.Add([PSCustomObject]@{
                DisplayName              = $cpc.displayName
                Status                   = $cpc.status
                IsDisasterRecoveryActive = $cpc.isDisasterRecoveryActive
                PrimaryRegion            = if ($cap) { $cap.primaryRegion } else { $null }
                SecondaryRegion          = if ($cap) { $cap.secondaryRegion } else { $null }
                CheckedAt                = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            })
        }

        if ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink' -Headers $headers -ErrorAction Stop
        } else {
            break
        }
    }
} catch {
    Write-Host "ERROR: Graph query failed: $_"
    exit 2
}

$failingOver  = $results | Where-Object { $_.Status -eq "failoverInProgress" }
$failingBack  = $results | Where-Object { $_.Status -eq "failbackInProgress" }
$activeInDr   = $results | Where-Object { $_.IsDisasterRecoveryActive -eq $true }

$affected = @($failingOver) + @($failingBack) + @($activeInDr) | Sort-Object DisplayName -Unique

if ($affected.Count -gt 0) {
    $affected | Format-List
}

Write-Host ("SUMMARY: {0} mid-failover, {1} mid-failback, {2} currently running from DR region" -f `
    $failingOver.Count, $failingBack.Count, $activeInDr.Count)
Write-Host ("Total Cloud PCs checked: {0}" -f $results.Count)

if ($CsvPath) {
    $csvDir = Split-Path -Path $CsvPath -Parent
    if ($csvDir -and -not (Test-Path $csvDir)) {
        New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
    }
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Force
    Write-Host "Full result set exported to $CsvPath"
}

if ($affected.Count -gt 0) {
    exit 1
} else {
    exit 0
}
