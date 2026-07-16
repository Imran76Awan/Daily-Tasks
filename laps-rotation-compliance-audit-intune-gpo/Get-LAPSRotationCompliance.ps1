<#
.SYNOPSIS
    Audits whether Windows LAPS local administrator passwords are ACTUALLY rotating across your
    managed device fleet — not just whether a LAPS policy is assigned in Intune or Group Policy.

.DESCRIPTION
    A device can show a Windows LAPS policy as "assigned" and "succeeded" in Intune, and still have
    a local Administrator password that hasn't rotated in months. This usually happens for one of
    three reasons:

      1. A conflict between the Intune Settings Catalog / CSP LAPS policy and a leftover on-prem
         Group Policy LAPS configuration (Computer Configuration > Administrative Templates > System
         > LAPS) — whichever policy "wins" on that device silently overrides the other's rotation
         schedule, and the loser's expiry timestamp just sits there aging.
      2. The device has stopped checking in to Intune / Entra ID entirely, so it never receives a
         rotation command, but nothing in the portal raises an obvious alert for this.
      3. The policy silently failed to apply (CSP error, corrupted local security policy cache, etc.)
         even though the device otherwise reports healthy and compliant.

    This script enumerates devices with a Windows LAPS credential record via Microsoft Graph
    (deviceLocalCredentialInfo), reads the most recent credential's passwordExpirationDateTime and
    backupDateTime, and classifies each device:

      GREEN  - passwordExpirationDateTime is in the future AND backupDateTime is recent
               (rotation is healthy)
      AMBER  - backupDateTime is older than -AmberThresholdDays (default 45) but the password has
               not technically expired yet - approaching staleness / possible check-in problem
      RED    - passwordExpirationDateTime is already in the past - rotation has stalled and the
               local admin password is stale

    For every AMBER/RED device, the script cross-references Intune's managed device record
    (Get-MgDeviceManagementManagedDevice) to check the device's LastSyncDateTime. This distinguishes:

      - "Policy conflict"  = device is checking in fine (recent LastSyncDateTime) but LAPS rotation
                             has stalled anyway. Likely a GPO vs. CSP conflict, or a policy that
                             silently failed to apply. Needs investigation on the device itself
                             (gpresult /h, Settings Catalog policy report).
      - "Device offline"   = device has not checked in for an extended period. Different root cause -
                             rotation was never going to happen because the device isn't talking to
                             Intune/Entra ID at all.

    IMPORTANT: This script has not yet been validated against a live tenant. Cmdlet names and
    property shapes are written to match the documented Microsoft Graph PowerShell SDK and Graph
    beta/v1.0 API surface for Windows LAPS as of mid-2026, but you should dry-run this against a
    small pilot group and sanity-check the output against the Entra portal (Devices > All devices >
    <device> > Local Administrator Password Recovery (LAPS)) before trusting it fleet-wide.

.NOTES
    Author:   Imran Awan
    Blog:     https://endpointweekly.com/blog/laps-rotation-compliance-audit-intune-gpo.html
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement,
              Microsoft.Graph.DeviceManagement modules (Install-Module Microsoft.Graph -Scope CurrentUser)
    Graph scopes required (delegated or app-only):
              Device.Read.All, DeviceLocalCredential.Read.All, DeviceManagementManagedDevices.Read.All
    Tested:   NOT yet tested against a production tenant. Validate on a pilot group first.

.PARAMETER AmberThresholdDays
    Number of days since the last credential backup before a device is flagged AMBER even though
    its current password has not technically expired yet. Default is 45.

.PARAMETER ExportCsv
    Optional path to export the full compliance report as CSV, e.g. C:\Reports\laps-compliance.csv

.PARAMETER TenantId
    Optional. Pass a specific tenant ID to Connect-MgGraph when working with multiple tenants.

.EXAMPLE
    .\Get-LAPSRotationCompliance.ps1

    Runs the audit against the current tenant with default thresholds and prints a colour-coded
    console report.

.EXAMPLE
    .\Get-LAPSRotationCompliance.ps1 -AmberThresholdDays 30 -ExportCsv "C:\Reports\laps-compliance-$(Get-Date -Format 'yyyyMMdd').csv"

    Runs the audit with a stricter 30-day amber threshold and exports the full results to CSV.

.EXAMPLE
    .\Get-LAPSRotationCompliance.ps1 -TenantId "contoso.onmicrosoft.com" -ExportCsv "C:\Reports\laps.csv"

    Runs the audit against a specific tenant and exports results.
#>

[CmdletBinding()]
param(
    [int]$AmberThresholdDays = 45,
    [string]$ExportCsv,
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 1. Connect to Microsoft Graph with the scopes needed to read LAPS credential
#    metadata, device records, and Intune managed device check-in state.
# ---------------------------------------------------------------------------
Write-Section "Connecting to Microsoft Graph"

$requiredScopes = @(
    "Device.Read.All",
    "DeviceLocalCredential.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)

$connectParams = @{
    Scopes   = $requiredScopes
    NoWelcome = $true
}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

Connect-MgGraph @connectParams

$context = Get-MgContext
Write-Host "Connected as $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Enumerate Entra ID devices and pull Intune managed device state (for the
#    LastSyncDateTime cross-check used later to distinguish "policy conflict"
#    from "device offline").
# ---------------------------------------------------------------------------
Write-Section "Enumerating devices"

Write-Host "Pulling Entra ID device list (Get-MgDevice -All)..." -ForegroundColor Gray
$entraDevices = Get-MgDevice -All -Property "Id,DeviceId,DisplayName,OperatingSystem,TrustType,ApproximateLastSignInDateTime"

Write-Host "Pulling Intune managed device list (Get-MgDeviceManagementManagedDevice -All)..." -ForegroundColor Gray
$managedDevices = Get-MgDeviceManagementManagedDevice -All -Property "Id,DeviceName,AzureAdDeviceId,LastSyncDateTime,ComplianceState"

# Index managed devices by their Entra device ID (AzureAdDeviceId) for fast lookup
$managedByAadDeviceId = @{}
foreach ($md in $managedDevices) {
    if ($md.AzureAdDeviceId) {
        $managedByAadDeviceId[$md.AzureAdDeviceId] = $md
    }
}

Write-Host "Found $($entraDevices.Count) Entra ID devices, $($managedDevices.Count) Intune-managed devices." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 3. For each device, retrieve its Windows LAPS credential info and evaluate
#    rotation compliance.
# ---------------------------------------------------------------------------
Write-Section "Evaluating LAPS rotation compliance"

$now = Get-Date
$results = New-Object System.Collections.Generic.List[object]

foreach ($device in $entraDevices) {

    # Only Windows devices are relevant for Windows LAPS
    if ($device.OperatingSystem -ne 'Windows') { continue }

    $deviceName = $device.DisplayName
    $status     = 'UNKNOWN'
    $reason     = ''
    $lastRotated = $null
    $expiresOn   = $null

    try {
        # Get-MgDirectoryDeviceLocalCredentialInfo returns a deviceLocalCredentialInfo object
        # containing a Credentials array. Each entry has PasswordExpirationDateTime and
        # BackupDateTime. We want the most recently backed-up credential.
        $credInfo = Get-MgDirectoryDeviceLocalCredentialInfo -DeviceLocalCredentialInfoId $device.DeviceId -ErrorAction Stop

        if (-not $credInfo -or -not $credInfo.Credentials -or $credInfo.Credentials.Count -eq 0) {
            $status = 'RED'
            $reason = 'No LAPS credential record found - LAPS has never backed up a password for this device'
        }
        else {
            $latestCred = $credInfo.Credentials | Sort-Object -Property BackupDateTime -Descending | Select-Object -First 1
            $lastRotated = $latestCred.BackupDateTime
            $expiresOn   = $latestCred.PasswordExpirationDateTime

            if ($expiresOn -and $expiresOn -lt $now) {
                $status = 'RED'
                $reason = "Password expired on $($expiresOn.ToString('yyyy-MM-dd HH:mm')) and has not been replaced"
            }
            elseif ($lastRotated -and (($now - $lastRotated).TotalDays -gt $AmberThresholdDays) ) {
                $status = 'AMBER'
                $reason = "Last rotation was $([math]::Round(($now - $lastRotated).TotalDays)) days ago (threshold: $AmberThresholdDays days)"
            }
            else {
                $status = 'GREEN'
                $reason = 'Rotation is current'
            }
        }
    }
    catch {
        # A 404 / not found here usually means Windows LAPS has never been provisioned on this
        # device at all - treat as RED, distinct from "expired" but equally in need of attention.
        $status = 'RED'
        $reason = "No LAPS record retrievable via Graph ($($_.Exception.Message))"
    }

    # Cross-check against Intune's own check-in timestamp to separate "policy conflict"
    # (device checks in fine, LAPS just isn't rotating) from "device offline" (hasn't
    # checked in at all, so of course rotation never happened).
    $rootCause = 'N/A'
    $lastSync  = $null
    if ($status -in @('RED', 'AMBER')) {
        $managed = $managedByAadDeviceId[$device.DeviceId]
        if ($managed) {
            $lastSync = $managed.LastSyncDateTime
            $daysSinceSync = if ($lastSync) { ($now - $lastSync).TotalDays } else { 9999 }

            if ($daysSinceSync -le 7) {
                $rootCause = 'Likely policy conflict (GPO vs CSP) - device checks in fine'
            }
            elseif ($daysSinceSync -le 30) {
                $rootCause = 'Check-in slipping - investigate connectivity'
            }
            else {
                $rootCause = 'Device offline - has not checked in for {0} days' -f [math]::Round($daysSinceSync)
            }
        }
        else {
            $rootCause = 'Not found in Intune managed devices - unmanaged or stale AD object'
        }
    }

    $results.Add([PSCustomObject]@{
        DeviceName        = $deviceName
        AzureAdDeviceId   = $device.DeviceId
        TrustType         = $device.TrustType
        Status            = $status
        Reason            = $reason
        LastRotated       = $lastRotated
        PasswordExpiresOn = $expiresOn
        IntuneLastSync    = $lastSync
        RootCause         = $rootCause
    })
}

# ---------------------------------------------------------------------------
# 4. Print the colour-coded console report.
# ---------------------------------------------------------------------------
Write-Section "LAPS rotation compliance report"

foreach ($r in ($results | Sort-Object -Property Status, DeviceName)) {
    switch ($r.Status) {
        'GREEN' {
            Write-Host ("[OK]    {0,-22} rotated {1}" -f $r.DeviceName, $r.LastRotated) -ForegroundColor Green
        }
        'AMBER' {
            Write-Host ("[WARN]  {0,-22} {1}  |  {2}" -f $r.DeviceName, $r.Reason, $r.RootCause) -ForegroundColor Yellow
        }
        'RED' {
            Write-Host ("[FAIL]  {0,-22} {1}  |  {2}" -f $r.DeviceName, $r.Reason, $r.RootCause) -ForegroundColor Red
        }
        default {
            Write-Host ("[?]     {0,-22} status unknown" -f $r.DeviceName) -ForegroundColor DarkGray
        }
    }
}

$greenCount = ($results | Where-Object Status -eq 'GREEN').Count
$amberCount = ($results | Where-Object Status -eq 'AMBER').Count
$redCount   = ($results | Where-Object Status -eq 'RED').Count

Write-Host ""
Write-Host "Summary: $greenCount GREEN | $amberCount AMBER | $redCount RED (out of $($results.Count) devices checked)" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 5. Optional CSV export.
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Full report exported to $ExportCsv" -ForegroundColor Gray
}

if ($redCount -gt 0) {
    Write-Host ""
    Write-Host "ACTION NEEDED: $redCount device(s) have stalled or missing LAPS rotation. Review RootCause column before remediating." -ForegroundColor Red
}
