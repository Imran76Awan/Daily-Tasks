#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement, Microsoft.Graph.DeviceManagement.Enrollment

<#
.SYNOPSIS
    Reports on Enrollment Status Page (ESP)-relevant provisioning state for Intune-managed Windows devices, read-only.

.DESCRIPTION
    Get-EspDeviceProvisioningReport.ps1 queries Microsoft Graph for Intune managed devices and, where a
    matching Windows Autopilot device identity exists, cross-references it to surface the fields that
    actually matter when someone reports "my ESP is stuck" or "my ESP failed but the app installed fine".

    Microsoft Graph v1.0 has no single "ESP phase" or "ESP status" property. This script does not invent
    one. Instead it reports the closest real, documented signals:

      From managedDevice (Get-MgDeviceManagementManagedDevice):
        - enrollmentProfileName   : the Autopilot deployment profile name recorded against the device
        - deviceEnrollmentType    : e.g. windowsAzureADJoin, windowsCoManagement, windowsAutoEnrollment
        - deviceRegistrationState : Entra device registration state (notRegistered, registered, etc.)
        - azureADRegistered       : whether the device is Microsoft Entra registered
        - managementAgent         : management channel (mdm, intuneClient, etc.)
        - enrolledDateTime        : when MDM enrollment completed
        - lastSyncDateTime        : last successful Intune check-in
        - complianceState         : current compliance state

      From windowsAutopilotDeviceIdentity (Get-MgDeviceManagementWindowsAutopilotDeviceIdentity),
      matched on serial number:
        - enrollmentState         : unknown, enrolled, pendingReset, failed, notContacted
        - lastContactedDateTime   : last time the device checked in with the Autopilot service
        - groupTag                : the Autopilot Group Tag, useful for confirming profile assignment intent

    The script flags devices worth a closer look using only these documented fields:
        - enrollmentState = 'failed' or 'notContacted' on the matching Autopilot identity
        - lastSyncDateTime older than -StaleSyncHours from now (default 24h) on an otherwise "enrolled" device
        - deviceRegistrationState not equal to 'registered'
        - enrollmentProfileName blank on a device that has a matching Autopilot record (profile not assigned
          or not yet applied)

    This script makes NO changes. It does not delete, wipe, retire, sync, or reassign anything. It only
    calls read (GET) Graph cmdlets. If any Graph call fails, the script writes a terminating error and
    exits with a non-zero exit code rather than silently continuing with partial data.

.PARAMETER StaleSyncHours
    Number of hours since the last successful Intune sync before a device is flagged as stale.
    Default is 24.

.PARAMETER Top
    Maximum number of managed Windows devices to pull from Graph. Default is 999 (a single page).
    Use a higher number for larger fleets; the script pages automatically via -All.

.PARAMETER OutputPath
    Optional path to export the results as CSV. If omitted, results are only written to the pipeline/host.

.EXAMPLE
    .\Get-EspDeviceProvisioningReport.ps1

    Connects to Graph interactively, reports on all Windows managed devices, flags anything stale or
    showing a failed/not-contacted Autopilot enrollment state, and prints a summary table to the host.

.EXAMPLE
    .\Get-EspDeviceProvisioningReport.ps1 -StaleSyncHours 8 -OutputPath C:\Reports\esp-fleet-check.csv

    Uses an 8-hour staleness threshold (useful right after a big Autopilot rollout day) and exports the
    full device-level detail to CSV.

.NOTES
    Author        : Imran Awan
    Blog post     : https://endpointweekly.com/blog/intune-enrollment-status-page-esp-configuration-troubleshooting.html
    Requires      : Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement,
                    Microsoft.Graph.DeviceManagement.Enrollment PowerShell modules
    Graph scopes  : DeviceManagementManagedDevices.Read.All, DeviceManagementServiceConfig.Read.All
    Read-only     : Yes. Only Get-Mg* cmdlets are called. No writes, deletes, syncs, or resets.

    Known limitation: Graph v1.0 does not expose a direct "ESP phase" (Device Setup / Account Setup) or
    per-app ESP tracking result for a managed device. That granular, per-app timing data lives only in the
    on-device MDM diagnostics report (Settings > Accounts > Access work or school > Export > Export your
    management log files, or the IME logs under
    C:\ProgramData\Microsoft\IntuneManagementExtension\Logs) — this script cannot substitute for pulling
    those logs when you need to see exactly which app tracked as failed and why. What this script gives you
    is a fast, fleet-wide triage signal so you know which devices are worth pulling those logs for.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$StaleSyncHours = 24,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$Top = 999,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph (read-only scopes only)
# ---------------------------------------------------------------------------
Write-Section "Connecting to Microsoft Graph"

try {
    $requiredScopes = @(
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All'
    )

    $context = Get-MgContext
    if (-not $context -or (Compare-Object -ReferenceObject $requiredScopes -DifferenceObject $context.Scopes | Where-Object { $_.SideIndicator -eq '<=' })) {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    }

    Select-MgProfile -Name "v1.0" -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------------------------
# Pull managed Windows devices
# ---------------------------------------------------------------------------
Write-Section "Retrieving managed Windows devices"

try {
    $managedDevices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'" -All -Top $Top -ErrorAction Stop
}
catch {
    Write-Error "Graph call to Get-MgDeviceManagementManagedDevice failed: $($_.Exception.Message)"
    exit 1
}

if (-not $managedDevices -or $managedDevices.Count -eq 0) {
    Write-Warning "No Windows managed devices were returned. Nothing to report."
    exit 0
}

Write-Host "Retrieved $($managedDevices.Count) Windows managed device(s)." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Pull Windows Autopilot device identities (read-only) for cross-reference
# ---------------------------------------------------------------------------
Write-Section "Retrieving Windows Autopilot device identities"

try {
    $autopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop
}
catch {
    Write-Error "Graph call to Get-MgDeviceManagementWindowsAutopilotDeviceIdentity failed: $($_.Exception.Message)"
    exit 1
}

Write-Host "Retrieved $($autopilotDevices.Count) Autopilot device identity record(s)." -ForegroundColor Green

# Index Autopilot identities by serial number for a fast, client-side join.
# (Server-side $filter on serialNumber has historically been unreliable for some tenants/API versions.)
$autopilotBySerial = @{}
foreach ($ap in $autopilotDevices) {
    if ($ap.SerialNumber) {
        $autopilotBySerial[$ap.SerialNumber] = $ap
    }
}

# ---------------------------------------------------------------------------
# Build the report
# ---------------------------------------------------------------------------
Write-Section "Building provisioning report"

$staleThreshold = (Get-Date).ToUniversalTime().AddHours(-1 * $StaleSyncHours)
$report = [System.Collections.Generic.List[object]]::new()

foreach ($device in $managedDevices) {

    $apMatch = $null
    if ($device.SerialNumber -and $autopilotBySerial.ContainsKey($device.SerialNumber)) {
        $apMatch = $autopilotBySerial[$device.SerialNumber]
    }

    $lastSync = $device.LastSyncDateTime
    $isStale  = $false
    if ($lastSync -and $lastSync -lt $staleThreshold) {
        $isStale = $true
    }

    $flags = [System.Collections.Generic.List[string]]::new()

    if ($apMatch) {
        if ($apMatch.EnrollmentState -in @('failed', 'notContacted')) {
            $flags.Add("AutopilotEnrollmentState=$($apMatch.EnrollmentState)")
        }
    }

    if ($isStale) {
        $flags.Add("StaleSync>$StaleSyncHours`h")
    }

    if ($device.DeviceRegistrationState -and $device.DeviceRegistrationState -ne 'registered') {
        $flags.Add("DeviceRegistrationState=$($device.DeviceRegistrationState)")
    }

    if ($apMatch -and [string]::IsNullOrWhiteSpace($device.EnrollmentProfileName)) {
        $flags.Add("NoEnrollmentProfileNameDespiteAutopilotRecord")
    }

    $report.Add([PSCustomObject]@{
        DeviceName              = $device.DeviceName
        SerialNumber            = $device.SerialNumber
        UserPrincipalName       = $device.UserPrincipalName
        EnrollmentProfileName   = $device.EnrollmentProfileName
        DeviceEnrollmentType    = $device.DeviceEnrollmentType
        DeviceRegistrationState = $device.DeviceRegistrationState
        AzureADRegistered       = $device.AzureADRegistered
        ManagementAgent         = $device.ManagementAgent
        ComplianceState         = $device.ComplianceState
        EnrolledDateTime        = $device.EnrolledDateTime
        LastSyncDateTime        = $lastSync
        AutopilotMatchFound     = [bool]$apMatch
        AutopilotEnrollmentState = if ($apMatch) { $apMatch.EnrollmentState } else { $null }
        AutopilotGroupTag       = if ($apMatch) { $apMatch.GroupTag } else { $null }
        AutopilotLastContacted  = if ($apMatch) { $apMatch.LastContactedDateTime } else { $null }
        NeedsReview             = ($flags.Count -gt 0)
        ReviewReasons           = ($flags -join '; ')
    })
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
Write-Section "Summary"

$needsReview = $report | Where-Object { $_.NeedsReview }

Write-Host "Total Windows devices reported on : $($report.Count)"
Write-Host "Devices flagged for review        : $($needsReview.Count)" -ForegroundColor $(if ($needsReview.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($needsReview.Count -gt 0) {
    Write-Section "Devices flagged for review"
    $needsReview | Select-Object DeviceName, SerialNumber, UserPrincipalName, ReviewReasons |
        Format-Table -AutoSize -Wrap
}

if ($OutputPath) {
    try {
        $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "`nFull report exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV to '$OutputPath': $($_.Exception.Message)"
        exit 1
    }
}

$report
