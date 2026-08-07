<#
.SYNOPSIS
    Exports all Intune-managed Windows devices that have not synced since August 2026 Patch Tuesday.

.DESCRIPTION
    Connects to Microsoft Graph using the Microsoft.Graph PowerShell SDK and retrieves all
    Windows managed devices from Intune. Filters for devices whose last sync timestamp is
    earlier than 12 August 2026 (Patch Tuesday) — a reliable proxy for devices that have
    not yet confirmed KB5101684 installation.

    Exports the results to a CSV file in the current directory for further analysis or
    use as a device group import in Entra ID.

    This script is the companion to the EndpointWeekly blog post on the August 2026
    Patch Tuesday guidance.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/windows-august-2026-patch-tuesday.html
    Created : 2026-08-07
    Version : 1.0

    Prerequisites:
    - Microsoft.Graph PowerShell SDK: Install-Module Microsoft.Graph -Scope CurrentUser
    - Permission: DeviceManagementManagedDevices.Read.All (delegated or application)
    - Run as a user with Intune Read access, or configure app-only authentication

.EXAMPLE
    .\Get-IntuneDevicesPendingAugustPatch.ps1

    Connects interactively, queries all Windows devices, and saves a CSV to the current directory.

.EXAMPLE
    .\Get-IntuneDevicesPendingAugustPatch.ps1

    Total Windows devices: 847
    Devices not synced since patch date: 63
    Report saved to: .\PendingAugustPatch_20260813.csv
#>

[CmdletBinding()]
param()

# Connect to Microsoft Graph with the required scope
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -ErrorAction Stop

# August 2026 Patch Tuesday release date
$patchDate = [datetime]"2026-08-12"

Write-Host "Querying all Windows managed devices in Intune..." -ForegroundColor Cyan

$devices = Get-MgDeviceManagementManagedDevice `
    -Filter "operatingSystem eq 'Windows'" `
    -Select "id,deviceName,osVersion,complianceState,lastSyncDateTime,userPrincipalName,managedDeviceOwnerType" `
    -All

Write-Host "Total Windows devices: $($devices.Count)"

# Filter devices that have not synced since Patch Tuesday
# These devices have not confirmed receipt and installation of KB5101684
$pending = $devices | Where-Object {
    [datetime]$_.lastSyncDateTime -lt $patchDate
}

Write-Host "Devices not synced since $($patchDate.ToString('dd MMM yyyy')): $($pending.Count)" -ForegroundColor Yellow

if ($pending.Count -gt 0) {
    $outputPath = ".\PendingAugustPatch_$(Get-Date -Format yyyyMMdd).csv"

    $pending |
        Select-Object deviceName, osVersion, complianceState, lastSyncDateTime, userPrincipalName, managedDeviceOwnerType |
        Sort-Object lastSyncDateTime |
        Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host "Report saved to: $outputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Use the CSV to build an Entra ID dynamic device group for non-synced devices" -ForegroundColor White
    Write-Host "  2. Scope an Intune Update Ring to that group to force KB5101684 deployment" -ForegroundColor White
    Write-Host "  3. Re-run this script after 48 hours to verify the count is decreasing" -ForegroundColor White
}
else {
    Write-Host "All devices have synced since Patch Tuesday. Fleet appears up to date." -ForegroundColor Green
}

Write-Host ""
Disconnect-MgGraph | Out-Null
