<#
.SYNOPSIS
    Audit every Windows Autopilot-registered device in the tenant against known
    hardware-eligibility red flags - without changing anything.

.DESCRIPTION
    "Registered with Windows Autopilot" and "hardware is actually eligible for
    Windows Autopilot" are not the same statement. This script pulls every
    windowsAutopilotDeviceIdentity record in the tenant via Microsoft Graph and
    flags the patterns that, in practice, correlate with a device that looked
    fine on paper but fails hardware hash capture, profile assignment, or
    Microsoft Entra join:

      - Missing or blank SerialNumber / Manufacturer / Model - Microsoft Learn
        documents InvalidZtdHardwareHash as occurring when manufacturer or
        serial number information is missing or empty in the uploaded hash.
      - Placeholder/generic SMBIOS values (e.g. "System Serial Number",
        "To be filled by O.E.M.", "Default string", "0123456789") - these are
        well-known symptoms of an OEM that never provisioned real SMBIOS Type 1
        fields, which is the guideline Autopilot device guidelines documents as
        a best-practice requirement, not an enforced one - so nothing stops a
        device shipping without it.
      - Duplicate SerialNumber values across the returned set - a real-world
        signature of refurbished/leased fleets or cloned VM templates, and the
        underlying cause behind ZtdDeviceDuplicated / ZtdDeviceAssignedToAnotherTenant
        errors during (re-)registration.
      - Registered devices with no ManagedDeviceId AND no AzureActiveDirectoryDeviceId
        AND a null LastContactedDateTime - registered with the Autopilot service
        but never once contacted it, which is a different and earlier failure
        point than "enrolled but stuck."
      - Devices with an AzureActiveDirectoryDeviceId but no ManagedDeviceId -
        joined to Microsoft Entra ID but never completed MDM enrollment, which
        is the specific gap between "Autopilot-capable" and "actually deployed."

    IMPORTANT - what this script deliberately does NOT claim to check:
    Microsoft Graph's windowsAutopilotDeviceIdentity resource (v1.0) does not
    expose a TPM version, TPM attestation state, or Secure Boot state property.
    Those checks (TPM 2.0 present / not in Reduced Functionality Mode, Secure
    Boot enabled) can only be confirmed on the physical device itself, for
    example with Get-Tpm and Confirm-SecureBootUEFI, or indirectly from Windows
    Autopilot event log entries (Event ID 171 - "failed to set TPM identity
    confirmed") on a device that has already attempted self-deploying mode.
    This script flags tenant-side registration data only; it cannot and does
    not claim to attest to a device's live TPM or Secure Boot state.

    This script is 100% read-only. It makes zero write, update, or delete calls
    to Microsoft Graph. It only queries windowsAutopilotDeviceIdentity objects
    and reports on them.

.PARAMETER Top
    Limit the query to the first N Autopilot records for a quick connectivity
    smoke test. Omit (or set 0) to audit every registered device in the tenant.

.PARAMETER ExportCsv
    If specified, exports the full flagged-device list to a timestamped CSV
    file in the same folder as the script.

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive
    device-code sign-in instead.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only certificate authentication. Requires
    the app registration to have DeviceManagementServiceConfig.Read.All granted
    as an Application permission with admin consent.

.NOTES
    Requires module: Microsoft.Graph.DeviceManagement.Enrollment
    Permission required (read-only, delegated or application):
      - DeviceManagementServiceConfig.Read.All

    This script makes NO write, update, or delete calls of any kind. It is safe
    to run against a production tenant with only the read permission above
    granted.

    Blog post: https://endpointweekly.com/blog/windows-autopilot-device-guidelines-hardware-requirements.html
    Author:    Imran Awan
    Version:   1.0

.EXAMPLE
    .\Get-AutopilotHardwareEligibilityAudit.ps1
    Interactive device-code sign-in, audits every registered device in the tenant.

.EXAMPLE
    .\Get-AutopilotHardwareEligibilityAudit.ps1 -Top 50
    Smoke test against the first 50 records only - counts below will not be
    a complete tenant picture.

.EXAMPLE
    .\Get-AutopilotHardwareEligibilityAudit.ps1 -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx" -ExportCsv
    App-only certificate authentication, full tenant audit, exported to CSV.
#>

[CmdletBinding()]
param (
    [int]$Top = 0,
    [switch]$ExportCsv,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

#region Prerequisites
$requiredModules = @('Microsoft.Graph.DeviceManagement.Enrollment')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod module..." -ForegroundColor Yellow
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            Write-Host "`nFailed to install required module '$mod': $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    try {
        Import-Module $mod -ErrorAction Stop
    } catch {
        Write-Host "`nFailed to import required module '$mod': $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$useAppOnlyAuth = $TenantId -and $ClientId -and $CertificateThumbprint

try {
    if ($useAppOnlyAuth) {
        Write-Host "Connecting to Microsoft Graph using app-only certificate auth..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop | Out-Null
    } else {
        Write-Host "Connecting to Microsoft Graph (read-only scope, device-code sign-in)..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All" -UseDeviceCode -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Host "`nFailed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Nothing was queried. Fix the connection and re-run - do not trust a '0 flagged' result unless you saw this script connect successfully." -ForegroundColor Red
    exit 1
}
#endregion

Write-Host "`n============================================================" -ForegroundColor White
Write-Host " WINDOWS AUTOPILOT HARDWARE ELIGIBILITY AUDIT (read-only)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

if ($Top -gt 0) {
    Write-Host "SMOKE TEST MODE - limiting the query to the first $Top records. Counts below will not reflect the whole tenant." -ForegroundColor Yellow
}

Write-Host "`nFetching Windows Autopilot device identities..." -ForegroundColor Cyan
try {
    if ($Top -gt 0) {
        $autopilotDevices = @(Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Top $Top -ErrorAction Stop)
    } else {
        $autopilotDevices = @(Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop)
    }
} catch {
    Write-Host "`nFailed to fetch Autopilot device identities: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Aborting - a '0 flagged' report after a failed query would be misleading, not a real result." -ForegroundColor Red
    exit 1
}

$totalCount = $autopilotDevices.Count
Write-Host "  Retrieved $totalCount Autopilot registration(s)" -ForegroundColor Gray

if ($totalCount -eq 0) {
    Write-Host "`nNo Autopilot device identities returned. Nothing to audit." -ForegroundColor Yellow
    return
}

# Known placeholder / unprovisioned SMBIOS strings that OEMs and virtualisation
# platforms leave behind when SMBIOS Type 1 fields were never properly set.
$placeholderStrings = @(
    'System Serial Number',
    'To Be Filled By O.E.M.',
    'Default string',
    'None',
    'Not Specified',
    '0123456789',
    'N/A',
    'Serial Number',
    '.',
    '1234567890'
)

#region Build duplicate serial-number lookup
$serialGroups = $autopilotDevices | Where-Object { $_.SerialNumber } | Group-Object -Property SerialNumber
$duplicateSerials = ($serialGroups | Where-Object { $_.Count -gt 1 }).Name
#endregion

$flagged = @()

foreach ($ap in $autopilotDevices) {

    $reasons = @()

    $serial = $ap.SerialNumber
    $manufacturer = $ap.Manufacturer
    $model = $ap.Model

    if ([string]::IsNullOrWhiteSpace($serial)) {
        $reasons += 'Missing SerialNumber'
    } elseif ($placeholderStrings -contains $serial.Trim()) {
        $reasons += "Placeholder SerialNumber value ('$serial')"
    }

    if ([string]::IsNullOrWhiteSpace($manufacturer)) {
        $reasons += 'Missing Manufacturer'
    } elseif ($placeholderStrings -contains $manufacturer.Trim()) {
        $reasons += "Placeholder Manufacturer value ('$manufacturer')"
    }

    if ([string]::IsNullOrWhiteSpace($model)) {
        $reasons += 'Missing Model'
    } elseif ($placeholderStrings -contains $model.Trim()) {
        $reasons += "Placeholder Model value ('$model')"
    }

    if ($serial -and $duplicateSerials -contains $serial) {
        $reasons += 'Duplicate SerialNumber elsewhere in this result set'
    }

    $neverContacted = (-not $ap.ManagedDeviceId) -and (-not $ap.AzureActiveDirectoryDeviceId) -and (-not $ap.LastContactedDateTime)
    if ($neverContacted) {
        $reasons += 'Registered but never contacted the Autopilot service (no ManagedDeviceId, no AzureActiveDirectoryDeviceId, no LastContactedDateTime)'
    }

    $entraJoinedNotEnrolled = ($ap.AzureActiveDirectoryDeviceId) -and (-not $ap.ManagedDeviceId)
    if ($entraJoinedNotEnrolled) {
        $reasons += 'Has an AzureActiveDirectoryDeviceId but no ManagedDeviceId - Entra join step reached, MDM enrollment did not complete'
    }

    if ($reasons.Count -gt 0) {
        $flagged += [PSCustomObject]@{
            SerialNumber                 = $serial
            Manufacturer                 = $manufacturer
            Model                        = $model
            GroupTag                     = $ap.GroupTag
            EnrollmentState              = $ap.EnrollmentState
            LastContactedDateTime        = $ap.LastContactedDateTime
            ManagedDeviceId               = $ap.ManagedDeviceId
            AzureActiveDirectoryDeviceId  = $ap.AzureActiveDirectoryDeviceId
            FlagReasons                   = ($reasons -join '; ')
        }
    }
}

#region Report
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " FLAGGED DEVICES ($($flagged.Count) of $totalCount)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

if ($flagged.Count -eq 0) {
    Write-Host "None found - no known hardware-eligibility red flags in the returned Autopilot records." -ForegroundColor Green
} else {
    foreach ($d in ($flagged | Sort-Object -Property SerialNumber)) {
        $serialLabel = if ($d.SerialNumber) { $d.SerialNumber } else { '(no serial)' }
        Write-Host "`n$serialLabel  [$($d.Manufacturer) $($d.Model)]  GroupTag: $($d.GroupTag)  EnrollmentState: $($d.EnrollmentState)" -ForegroundColor Yellow
        Write-Host "  Reasons: $($d.FlagReasons)" -ForegroundColor Red
    }
}

Write-Host "`n------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Reminder: this script cannot see live TPM 2.0 state or Secure Boot state." -ForegroundColor Gray
Write-Host "Those require an on-device check (Get-Tpm / Confirm-SecureBootUEFI) or the" -ForegroundColor Gray
Write-Host "ModernDeployment-Diagnostics-Provider/Autopilot event log (Event ID 171)." -ForegroundColor Gray
Write-Host "------------------------------------------------------------" -ForegroundColor Gray
#endregion

#region Export
if ($ExportCsv) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $exportPath = Join-Path $PSScriptRoot "AutopilotHardwareEligibilityFlags-$stamp.csv"
    try {
        $flagged | Export-Csv -Path $exportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "`nExported: $exportPath" -ForegroundColor Green
    } catch {
        Write-Host "`nFailed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
#endregion

return $flagged
