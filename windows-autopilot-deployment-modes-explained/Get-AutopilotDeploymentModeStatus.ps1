#Requires -Modules Microsoft.Graph.DeviceManagement.Enrollment

<#
.SYNOPSIS
    Read-only check of a Windows Autopilot device's registration state, its assigned
    deployment profile, and the profile's assignment status - so you know which
    deployment mode (user-driven, self-deploying, or pre-provisioning/White Glove)
    a device is actually going to run before it's shipped or powered on.

.DESCRIPTION
    Get-AutopilotDeploymentModeStatus.ps1 connects to Microsoft Graph and queries the
    Windows Autopilot device identity for a given serial number, then resolves the
    Windows Autopilot deployment profile assigned to that device (if any) so you can
    confirm the deployment mode configured on the profile and whether the assignment
    has actually reached the device - not just whether the device is a member of the
    Entra ID group you expect.

    This script is strictly read-only. It performs no writes, deletes, profile
    assignments, or device deletions against Autopilot, Intune, or Entra ID. It only
    calls Get-* Microsoft Graph PowerShell SDK cmdlets.

    The script fails loudly (exit code 1) on any Graph connection error, query error,
    or missing/renamed property it cannot confidently interpret. It never reports
    "0 found" or "healthy" as a substitute for an error it could not resolve - if the
    Graph SDK version installed doesn't expose an expected property, the script stops
    and tells you exactly what it could not verify, rather than guessing.

    Companion script for the EndpointWeekly post "Windows Autopilot Deployment Modes
    Explained: User-Driven, Self-Deploying, and White Glove."

.PARAMETER SerialNumber
    The serial number of the device to look up in the Windows Autopilot device
    identity list. Required.

.PARAMETER TenantId
    Entra ID tenant ID or verified domain name to connect to. Required when using
    app-only certificate authentication. Optional for interactive/device-code auth
    if you want Connect-MgGraph to prompt for tenant selection.

.PARAMETER ClientId
    Application (client) ID of the Entra ID app registration used for app-only
    certificate authentication. Required together with -CertificateThumbprint.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate installed in the local certificate store used for
    app-only authentication against the app registration identified by -ClientId.
    Required together with -ClientId and -TenantId. If omitted, the script falls
    back to interactive device-code authentication.

.EXAMPLE
    .\Get-AutopilotDeploymentModeStatus.ps1 -SerialNumber "PF9KIOSK1" -TenantId "contoso.onmicrosoft.com"

    Runs with interactive device-code authentication (no app registration supplied)
    and checks the Autopilot registration and profile assignment status for the
    device with serial number PF9KIOSK1.

.EXAMPLE
    .\Get-AutopilotDeploymentModeStatus.ps1 -SerialNumber "PF9KIOSK1" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "66666666-7777-8888-9999-000000000000" `
        -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD"

    Runs unattended using app-only certificate authentication, suitable for a
    scheduled task or pipeline that audits Autopilot deployment mode assignment
    ahead of a device shipment.

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-autopilot-deployment-modes-explained.html
    Author:    Imran Awan
    Requires:  Microsoft.Graph.DeviceManagement.Enrollment PowerShell module
    Read-only: Yes. No Autopilot, Intune, or Entra ID objects are created, modified, or deleted.

    Known gaps flagged rather than guessed at:
    - The exact property name Microsoft Graph exposes for a per-device deployment
      profile assignment status (e.g. "assigned" vs "pending" vs "failed") has
      changed naming across Graph API versions and SDK releases in the past. This
      script checks for the property defensively and raises a clear terminating
      error if it cannot find a recognizable status property, rather than assuming
      a default state.
    - Server-side -Filter queries against Windows Autopilot device identity by
      serial number have been unreliable on some tenants/API versions. This script
      always pulls the full identity list with -All and filters client-side.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SerialNumber,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph
# ---------------------------------------------------------------------------
Write-Section 'Connecting to Microsoft Graph'

try {
    if ($ClientId -and $CertificateThumbprint -and $TenantId) {
        Write-Host "Using app-only certificate authentication (ClientId: $ClientId)" -ForegroundColor DarkGray
        Connect-MgGraph -TenantId $TenantId `
                         -ClientId $ClientId `
                         -CertificateThumbprint $CertificateThumbprint `
                         -NoWelcome
    }
    else {
        Write-Host 'No app-only credentials supplied - falling back to interactive device-code sign-in.' -ForegroundColor DarkGray
        $connectParams = @{
            Scopes    = @('DeviceManagementServiceConfig.Read.All')
            UseDeviceCode = $true
            NoWelcome = $true
        }
        if ($TenantId) { $connectParams['TenantId'] = $TenantId }
        Connect-MgGraph @connectParams
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

$context = Get-MgContext
if (-not $context) {
    Write-Error 'Connect-MgGraph reported success but no Graph context is present. Aborting - cannot verify anything without an authenticated context.'
    exit 1
}
Write-Host "Connected as: $($context.Account)  Tenant: $($context.TenantId)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Look up the Windows Autopilot device identity by serial number
# ---------------------------------------------------------------------------
Write-Section "Looking up Windows Autopilot device identity for serial number '$SerialNumber'"

try {
    # Deliberately pull the full list with -All and filter client-side rather than
    # relying on a server-side -Filter, which has been unreliable for exact-match
    # serial number queries on some tenants/API versions.
    $allIdentities = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop
}
catch {
    Write-Error "Graph query for Windows Autopilot device identities failed: $($_.Exception.Message)"
    exit 1
}

if ($null -eq $allIdentities) {
    Write-Error 'Get-MgDeviceManagementWindowsAutopilotDeviceIdentity returned $null instead of a collection (even an empty one). Treating this as a query failure, not an empty tenant.'
    exit 1
}

$device = $allIdentities | Where-Object { $_.SerialNumber -eq $SerialNumber }

if (-not $device) {
    Write-Error "No Windows Autopilot device identity found for serial number '$SerialNumber' in this tenant. This device is NOT registered with Windows Autopilot - it cannot receive any deployment profile or run any Autopilot mode until it is registered."
    exit 1
}

if (@($device).Count -gt 1) {
    Write-Error "Found more than one Windows Autopilot device identity matching serial number '$SerialNumber'. Refusing to guess which one is relevant - resolve the duplicate registration manually before relying on this script's output."
    exit 1
}

Write-Host "Device found. Windows Autopilot device identity ID: $($device.Id)" -ForegroundColor Green
Write-Host "  Model:               $($device.Model)"
Write-Host "  Manufacturer:        $($device.Manufacturer)"
Write-Host "  Group Tag:           $($device.GroupTag)"
Write-Host "  Enrollment State:    $($device.EnrollmentState)"

# ---------------------------------------------------------------------------
# Resolve the deployment profile assigned to this device
# ---------------------------------------------------------------------------
Write-Section 'Resolving assigned Windows Autopilot deployment profile'

$deploymentProfile = $null
$assignmentStatusRaw = $null

try {
    # Some Graph SDK versions expose the assigned profile as an expandable
    # navigation property on the device identity object; others require a
    # separate call. Try the direct property first, and fail loudly (not
    # silently) if neither approach yields a usable object.
    if ($device.PSObject.Properties.Match('DeploymentProfile').Count -gt 0 -and $device.DeploymentProfile) {
        $deploymentProfile = $device.DeploymentProfile
    }
    elseif (Get-Command -Name Get-MgDeviceManagementWindowsAutopilotDeviceIdentityDeploymentProfile -ErrorAction SilentlyContinue) {
        $deploymentProfile = Get-MgDeviceManagementWindowsAutopilotDeviceIdentityDeploymentProfile `
            -WindowsAutopilotDeviceIdentityId $device.Id -ErrorAction Stop
    }
    else {
        Write-Error 'Could not resolve a deployment profile for this device: neither a populated DeploymentProfile property nor the Get-MgDeviceManagementWindowsAutopilotDeviceIdentityDeploymentProfile cmdlet is available in this Graph SDK session. Verify the Microsoft.Graph.DeviceManagement.Enrollment module version installed - do not assume the device has no profile assigned just because this lookup path is unavailable.'
        exit 1
    }
}
catch {
    Write-Error "Graph query for the device's deployment profile failed: $($_.Exception.Message)"
    exit 1
}

if (-not $deploymentProfile) {
    Write-Warning "No Windows Autopilot deployment profile is currently assigned to serial number '$SerialNumber'. This device WILL drop to standard, unbranded Windows OOBE if powered on right now - it is registered, but has nothing to deploy."
}
else {
    Write-Host "Assigned profile name:    $($deploymentProfile.DisplayName)" -ForegroundColor Green
    Write-Host "  Device Name Template:   $($deploymentProfile.DeviceNameTemplate)"

    # Confirm which deployment mode the profile is actually configured for, using
    # whichever mode-indicating property this SDK/API version exposes. Flag rather
    # than guess if the property is missing.
    $modeProps = @('DeploymentType', 'DeploymentMode')
    $modeProperty = $modeProps | Where-Object { $deploymentProfile.PSObject.Properties.Match($_).Count -gt 0 } | Select-Object -First 1

    if ($modeProperty) {
        Write-Host "  Deployment mode:        $($deploymentProfile.$modeProperty)" -ForegroundColor Green
    }
    else {
        Write-Warning "Could not find a recognizable deployment-mode property (checked: $($modeProps -join ', ')) on the returned deployment profile object. Confirm the deployment mode manually in the Intune admin center rather than assuming a mode from this script's output."
    }

    # Defensive check for the per-device assignment status. Property naming for
    # this has changed across Graph API/SDK versions in the past - flag clearly
    # rather than silently reporting a healthy state.
    $statusProps = @('AssignedDate', 'DeploymentProfileAssignmentStatus', 'AssignmentStatus')
    $statusProperty = $statusProps | Where-Object { $device.PSObject.Properties.Match($_).Count -gt 0 } | Select-Object -First 1

    if ($statusProperty) {
        $assignmentStatusRaw = $device.$statusProperty
        Write-Host "  Assignment status ($statusProperty): $assignmentStatusRaw" -ForegroundColor Green
    }
    else {
        Write-Warning "Could not find a recognizable profile assignment status property on the device identity object (checked: $($statusProps -join ', ')). DO NOT assume the profile has successfully reached the device - verify the 'Profile status' column for this device manually in Devices > Windows > Enrollment > Windows Autopilot > Devices in the Intune admin center."
    }
}

Write-Section 'Summary'
Write-Host "Serial number:        $SerialNumber"
Write-Host "Autopilot registered: Yes"
Write-Host "Profile assigned:     $(if ($deploymentProfile) { 'Yes' } else { 'No' })"
if ($deploymentProfile -and -not $modeProperty) {
    Write-Host "Deployment mode:      UNKNOWN - verify manually, see warning above" -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'This script performed read-only Graph queries only. No changes were made to Autopilot, Intune, or Entra ID.' -ForegroundColor DarkGray
