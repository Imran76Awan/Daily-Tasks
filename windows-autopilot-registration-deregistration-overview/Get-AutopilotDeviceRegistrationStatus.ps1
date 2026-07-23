<#
.SYNOPSIS
    Check a Windows Autopilot device's full registration, enrollment, and Entra
    object status in one call - before you attempt to deregister it.

.DESCRIPTION
    Combines three separate checks Microsoft's own deregistration guidance tells
    you to do by hand across three different portals into a single script:

      1. Is this serial number registered with Windows Autopilot at all?
      2. Is it currently enrolled in Intune (has a managed device record)?
      3. Does a Microsoft Entra device object exist for it, and is it Entra
         joined or hybrid Entra joined?

    Run this BEFORE deregistering a device to confirm its current state, and
    run it again AFTER to confirm what actually happened - Microsoft's docs are
    explicit that the Entra device object's fate after deregistration depends
    on whether the device was ever enrolled in MDM, so "it's gone from
    Autopilot" does not always mean "it's gone from Entra ID too."

    This script is read-only. It makes no changes to Autopilot, Intune, or
    Entra ID.

.PARAMETER SerialNumber
    The serial number of the device to check.

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive
    device-code sign-in instead.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only certificate authentication. Requires
    the app registration to have DeviceManagementServiceConfig.Read.All,
    DeviceManagementManagedDevices.Read.All, and Device.Read.All granted as
    Application permissions with admin consent.

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-autopilot-registration-deregistration-overview.html
    Author:    Imran Awan
    Version:   1.0

.EXAMPLE
    .\Get-AutopilotDeviceRegistrationStatus.ps1 -SerialNumber "PF3ABC12"
    Interactive device-code sign-in, checks one device.

.EXAMPLE
    .\Get-AutopilotDeviceRegistrationStatus.ps1 -SerialNumber "PF3ABC12" -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx"
    App-only certificate authentication, no interactive sign-in required.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$SerialNumber,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

#region Prerequisites
$requiredModules = @(
    'Microsoft.Graph.DeviceManagement.Enrollment',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Identity.DirectoryManagement'
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod module..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force
    }
    Import-Module $mod -ErrorAction Stop
}

$useAppOnlyAuth = $TenantId -and $ClientId -and $CertificateThumbprint

try {
    if ($useAppOnlyAuth) {
        Write-Host "Connecting to Microsoft Graph using app-only certificate auth..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
    } else {
        Write-Host "Connecting to Microsoft Graph (read-only scopes)..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementManagedDevices.Read.All", "Device.Read.All" -UseDeviceCode -ErrorAction Stop
    }
} catch {
    Write-Host "`nFailed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

Write-Host "`n============================================================" -ForegroundColor White
Write-Host " AUTOPILOT DEVICE REGISTRATION STATUS - $SerialNumber" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

#region 1. Autopilot registration
Write-Host "`n[1] Checking Windows Autopilot registration..." -ForegroundColor Cyan
try {
    $allAutopilot = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop
} catch {
    Write-Host "Failed to query Autopilot device identities: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
$autopilotDevice = $allAutopilot | Where-Object { $_.SerialNumber -eq $SerialNumber }

if ($autopilotDevice) {
    Write-Host "  REGISTERED with Windows Autopilot" -ForegroundColor Green
    Write-Host "    Manufacturer/Model    : $($autopilotDevice.Manufacturer) / $($autopilotDevice.Model)"
    Write-Host "    Group Tag             : $($autopilotDevice.GroupTag)"
    Write-Host "    Enrollment State      : $($autopilotDevice.EnrollmentState)"
    Write-Host "    Managed Device Id     : $($autopilotDevice.ManagedDeviceId)"
    Write-Host "    Azure AD Device Id    : $($autopilotDevice.AzureActiveDirectoryDeviceId)"
} else {
    Write-Host "  NOT REGISTERED with Windows Autopilot" -ForegroundColor Yellow
}
#endregion

#region 2. Intune managed device
Write-Host "`n[2] Checking Intune enrollment..." -ForegroundColor Cyan
try {
    $managedDevice = $null
    if ($autopilotDevice -and $autopilotDevice.ManagedDeviceId -and $autopilotDevice.ManagedDeviceId -ne [guid]::Empty.ToString()) {
        $managedDevice = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $autopilotDevice.ManagedDeviceId -ErrorAction SilentlyContinue
    }
    if (-not $managedDevice) {
        $managedDevice = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$SerialNumber'" -ErrorAction Stop | Select-Object -First 1
    }
} catch {
    Write-Host "Failed to query managed devices: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($managedDevice) {
    Write-Host "  ENROLLED in Intune (has a managed device record)" -ForegroundColor Green
    Write-Host "    Device Name           : $($managedDevice.DeviceName)"
    Write-Host "    Compliance State      : $($managedDevice.ComplianceState)"
    Write-Host "    Last Sync             : $($managedDevice.LastSyncDateTime)"
    Write-Host "    Join Type             : $($managedDevice.JoinType)"
} else {
    Write-Host "  NOT ENROLLED - no managed device record found" -ForegroundColor Yellow
}
#endregion

#region 3. Entra device object
Write-Host "`n[3] Checking Microsoft Entra device object..." -ForegroundColor Cyan
try {
    $entraDevice = $null
    if ($autopilotDevice -and $autopilotDevice.AzureActiveDirectoryDeviceId) {
        $entraDevice = Get-MgDevice -Filter "deviceId eq '$($autopilotDevice.AzureActiveDirectoryDeviceId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $entraDevice -and $managedDevice -and $managedDevice.AzureAdDeviceId) {
        $entraDevice = Get-MgDevice -Filter "deviceId eq '$($managedDevice.AzureAdDeviceId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
} catch {
    Write-Host "Failed to query Entra device objects: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($entraDevice) {
    Write-Host "  Entra device object EXISTS" -ForegroundColor Green
    Write-Host "    Display Name          : $($entraDevice.DisplayName)"
    Write-Host "    Trust Type            : $($entraDevice.TrustType)"
    Write-Host "    Registration DateTime : $($entraDevice.RegistrationDateTime)"
    Write-Host "    Account Enabled       : $($entraDevice.AccountEnabled)"
} else {
    Write-Host "  No Entra device object found for this serial number" -ForegroundColor Yellow
}
#endregion

Write-Host "`n============================================================" -ForegroundColor White
Write-Host " SUMMARY" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host "Autopilot registered : $([bool]$autopilotDevice)"
Write-Host "Intune enrolled      : $([bool]$managedDevice)"
Write-Host "Entra object exists  : $([bool]$entraDevice)"

if ($autopilotDevice -and -not $managedDevice) {
    Write-Host "`nNote: registered with Autopilot but not enrolled - this device has never signed in, or was already removed from Intune." -ForegroundColor Cyan
}
if (-not $autopilotDevice -and $entraDevice) {
    Write-Host "`nNote: no Autopilot registration but an Entra device object still exists - this matches Microsoft's documented behaviour for devices that were previously enrolled in MDM before Autopilot deregistration." -ForegroundColor Cyan
}
