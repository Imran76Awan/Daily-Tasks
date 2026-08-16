<#
.SYNOPSIS
    Finds Entra ID devices that Conditional Access currently trusts as "compliant" even
    though the underlying Intune compliance signal has not refreshed in a long time.

.DESCRIPTION
    Conditional Access policies that use the "Require device to be marked as compliant"
    grant control do not ask a device to prove its posture at sign-in. They read the
    isCompliant flag already stored on the device object in Entra ID. That flag was set
    the last time the device successfully checked in with Intune and passed compliance
    evaluation - not at the moment access is requested.

    This script pulls every Entra ID device object (Microsoft Graph /devices), pulls the
    matching Intune managed device record (Microsoft Graph /deviceManagement/managedDevices),
    and compares each compliant device's Intune lastSyncDateTime against the current time.
    Devices that are marked isCompliant = true but have not completed a successful sync
    within the configured staleness threshold are flagged as trusting an old signal.

    This is read-only. It only issues Invoke-MgGraphRequest GET calls. It does not change
    compliance state, does not sync devices, and does not modify any Conditional Access
    policy.

    Blog post: https://endpointweekly.com/blog/entra-conditional-access-stale-compliance-signal-audit.html

.PARAMETER TenantId
    The Entra ID tenant ID (GUID or verified domain) to connect to.

.PARAMETER ClientId
    The application (client) ID of the app registration used for app-only auth.

.PARAMETER CertificateThumbprint
    The certificate thumbprint used for app-only (client credential) authentication.
    Required unless -UseDeviceCode is specified.

.PARAMETER UseDeviceCode
    Falls back to interactive device code sign-in instead of certificate auth. Useful for
    a one-off run from an admin workstation. Requires delegated permissions instead of
    application permissions.

.PARAMETER StalenessThresholdDays
    Number of days since a device's last successful Intune sync before a "compliant"
    device is flagged as trusting a stale signal. Default is 3 days, which is well beyond
    the roughly 8-hour maintenance check-in cadence Intune documents for healthy devices.

.PARAMETER ExportCsv
    Switch to export results to a CSV file.

.PARAMETER CsvPath
    Path to write the CSV export. Defaults to .\StaleCompliantDevices.csv in the current
    directory when -ExportCsv is used without a path.

.EXAMPLE
    .\Find-StaleCompliantDevices.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "{aaaaaaaa-0b0b-1c1c-2d2d-333333333333}" -CertificateThumbprint "A1B2C3D4E5F6..."

    Runs with the default 3-day staleness threshold using app-only certificate auth.

.EXAMPLE
    .\Find-StaleCompliantDevices.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "{aaaaaaaa-0b0b-1c1c-2d2d-333333333333}" -UseDeviceCode -StalenessThresholdDays 5 -ExportCsv -CsvPath "C:\Reports\stale-compliance.csv"

    Runs interactively with device code sign-in, a 5-day threshold, and exports to CSV.

.NOTES
    Author: Imran Awan
    Blog: https://endpointweekly.com/blog/entra-conditional-access-stale-compliance-signal-audit.html
    Requires: Microsoft.Graph.Authentication module
    Required Graph permissions (application): Device.Read.All, DeviceManagementManagedDevices.Read.All
    Required Graph permissions (delegated, -UseDeviceCode): Device.Read.All, DeviceManagementManagedDevices.Read.All
    Read-only. No New-/Set-/Remove-/Update-/Add- calls, no Invoke- calls with side effects.
    Exit codes: 0 = clean, no stale compliant devices found. 1 = findings present. 2 = error.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [int]$StalenessThresholdDays = 3,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = ".\StaleCompliantDevices.csv"
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

try {
    Write-Section "Connecting to Microsoft Graph"

    if (-not $UseDeviceCode -and [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        throw "You must supply -CertificateThumbprint for app-only auth, or pass -UseDeviceCode for interactive sign-in."
    }

    if ($UseDeviceCode) {
        Write-Host "Using interactive device code sign-in."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes "Device.Read.All","DeviceManagementManagedDevices.Read.All" -UseDeviceCode -NoWelcome
    }
    else {
        Write-Host "Using app-only certificate authentication."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    }

    Write-Section "Retrieving Entra ID device objects (isCompliant = true)"

    $entraDevices = @()
    $selectFields = "id,deviceId,displayName,operatingSystem,isCompliant,complianceExpirationDateTime,approximateLastSignInDateTime,trustType"
    $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=isCompliant eq true&`$select=$selectFields&`$top=999"

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -Headers @{ ConsistencyLevel = "eventual" }
        if ($response.value) { $entraDevices += $response.value }
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    Write-Host "Found $($entraDevices.Count) Entra ID device objects currently marked isCompliant = true."

    if ($entraDevices.Count -eq 0) {
        Write-Host "No compliant devices found. Nothing to check. Exiting clean."
        Disconnect-MgGraph | Out-Null
        exit 0
    }

    Write-Section "Retrieving Intune managed device sync state"

    $managedDevices = @()
    $mdSelect = "id,azureADDeviceId,deviceName,operatingSystem,complianceState,lastSyncDateTime,complianceGracePeriodExpirationDateTime"
    $mdUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=$mdSelect&`$top=999"

    do {
        $mdResponse = Invoke-MgGraphRequest -Method GET -Uri $mdUri
        if ($mdResponse.value) { $managedDevices += $mdResponse.value }
        $mdUri = $mdResponse.'@odata.nextLink'
    } while ($mdUri)

    Write-Host "Retrieved $($managedDevices.Count) Intune managed device records."

    # Index managed devices by azureADDeviceId for a fast lookup against the Entra deviceId.
    $managedByAadId = @{}
    foreach ($md in $managedDevices) {
        if (-not [string]::IsNullOrWhiteSpace($md.azureADDeviceId)) {
            $managedByAadId[$md.azureADDeviceId] = $md
        }
    }

    Write-Section "Comparing compliance signal age against a $StalenessThresholdDays-day threshold"

    $now = [DateTime]::UtcNow
    $findings = New-Object System.Collections.Generic.List[Object]

    foreach ($device in $entraDevices) {
        $match = $managedByAadId[$device.deviceId]

        if (-not $match) {
            # A compliant Entra device with no matching Intune record at all is its own
            # red flag - the signal has no live source to refresh it. Treat as stale.
            $findings.Add([PSCustomObject]@{
                DisplayName           = $device.displayName
                OperatingSystem       = $device.operatingSystem
                TrustType             = $device.trustType
                IsCompliant           = $device.isCompliant
                LastSyncDateTime      = $null
                DaysSinceLastSync     = "N/A - no Intune record"
                ComplianceExpiration  = $device.complianceExpirationDateTime
                Reason                = "No matching Intune managed device record found"
            })
            continue
        }

        if ([string]::IsNullOrWhiteSpace($match.lastSyncDateTime)) {
            continue
        }

        $lastSync = [DateTime]::Parse($match.lastSyncDateTime).ToUniversalTime()
        $daysSinceSync = [Math]::Round(($now - $lastSync).TotalDays, 1)

        if ($daysSinceSync -ge $StalenessThresholdDays) {
            $findings.Add([PSCustomObject]@{
                DisplayName           = $device.displayName
                OperatingSystem       = $device.operatingSystem
                TrustType             = $device.trustType
                IsCompliant           = $device.isCompliant
                LastSyncDateTime      = $match.lastSyncDateTime
                DaysSinceLastSync     = $daysSinceSync
                ComplianceExpiration  = $device.complianceExpirationDateTime
                Reason                = "Intune last sync is $daysSinceSync days old but Entra still reports compliant"
            })
        }
    }

    Write-Section "Results"

    if ($findings.Count -eq 0) {
        Write-Host "No stale compliant devices found. Every compliant device has synced within $StalenessThresholdDays day(s)." -ForegroundColor Green
        Disconnect-MgGraph | Out-Null
        exit 0
    }

    Write-Host "$($findings.Count) device(s) are trusted as compliant by Conditional Access despite a stale or missing sync signal:" -ForegroundColor Yellow
    $findings | Sort-Object DaysSinceLastSync -Descending | Format-Table DisplayName, OperatingSystem, DaysSinceLastSync, LastSyncDateTime, Reason -AutoSize

    if ($ExportCsv) {
        $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Findings exported to $CsvPath"
    }

    Disconnect-MgGraph | Out-Null
    exit 1
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 2
}
