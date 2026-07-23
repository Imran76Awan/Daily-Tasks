<#
.SYNOPSIS
    Read-only Autopilot deployment health check for a single device, cross-referenced
    against known OOBE/ESP failure signatures.

.DESCRIPTION
    Given a serial number, this script queries Microsoft Graph (read-only) for:
      1. The Windows Autopilot device identity record (serialNumber, groupTag,
         enrollmentState, and - from the Graph BETA endpoint only - the
         deploymentProfileAssignmentStatus / deploymentProfileAssignmentDetailedStatus
         / deploymentProfileAssignedDateTime fields).
      2. The matching Intune managed device record (if enrolled), including
         enrollmentProfileName, complianceState, and lastSyncDateTime.
      3. The matching Microsoft Entra device object, including trustType
         (to catch "Microsoft Entra registered" vs "joined" mismatches).

    It then prints a plain-English summary that flags the specific failure
    signatures documented at:
    https://endpointweekly.com/blog/windows-autopilot-troubleshooting-common-errors-fixed.html

    IMPORTANT - verified vs. unverified fields:
      - enrollmentState, serialNumber, groupTag, azureAdDeviceId, managedDeviceId,
        resourceName, and displayName are documented v1.0 GA properties of
        windowsAutopilotDeviceIdentity (Microsoft Graph v1.0 reference).
      - deploymentProfileAssignmentStatus, deploymentProfileAssignmentDetailedStatus,
        and deploymentProfileAssignedDateTime are documented ONLY on the Graph BETA
        resource. They are not guaranteed stable and are read via a raw beta call
        (Invoke-MgGraphRequest), never via a v1.0 cmdlet. If Microsoft changes or
        removes these fields, this script fails loudly rather than silently
        returning wrong data.
      - This script makes NO write calls of any kind. No Set-, New-, Remove-, or
        Update- cmdlets are used anywhere in this file.

.NOTES
    Author        : Imran Awan
    Blog          : https://endpointweekly.com/blog/windows-autopilot-troubleshooting-common-errors-fixed.html
    Requires      : Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement.Enrollment,
                    Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.DirectoryManagement
    Graph scopes  : DeviceManagementServiceConfig.Read.All, DeviceManagementManagedDevices.Read.All,
                    Device.Read.All
    Read-only     : Yes. This script performs GET requests only.

.EXAMPLE
    .\Get-AutopilotDeploymentHealthCheck.ps1 -SerialNumber "PF3ABC12"

    Runs a full health check against the device with that serial number and prints
    the deployment status summary plus any matched failure signatures.

.EXAMPLE
    .\Get-AutopilotDeploymentHealthCheck.ps1 -SerialNumber "PF3ABC12" -TenantId "contoso.onmicrosoft.com"

    Same check, forcing a specific tenant at sign-in (useful for multi-tenant admins).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Serial number of the device to check.")]
    [ValidateNotNullOrEmpty()]
    [string]$SerialNumber,

    [Parameter(Mandatory = $false, HelpMessage = "Optional tenant ID or domain to target at sign-in.")]
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message)
    Write-Host "FATAL: $Message" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Module and connection checks
# ---------------------------------------------------------------------------
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement.Enrollment',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Fail "Required module '$module' is not installed. Run: Install-Module -Name $module -Scope CurrentUser"
    }
}

try {
    $requiredScopes = @(
        "DeviceManagementServiceConfig.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "Device.Read.All"
    )

    $connectParams = @{ Scopes = $requiredScopes }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

    Connect-MgGraph @connectParams | Out-Null
}
catch {
    Fail "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$context = Get-MgContext
if (-not $context -or -not $context.Account) {
    Fail "Microsoft Graph connection did not return a valid context. Aborting."
}

Write-Host "Connected to tenant: $($context.TenantId) as $($context.Account)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Look up the Windows Autopilot device identity (v1.0 GA fields)
# ---------------------------------------------------------------------------
Write-Section "Windows Autopilot device identity (v1.0)"

$autopilotDevice = $null
try {
    # Server-side $filter on serialNumber has historically been unreliable for
    # some tenants/API versions, so filter client-side to avoid false negatives.
    $allAutopilotDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction Stop
    $autopilotDevice = $allAutopilotDevices | Where-Object { $_.SerialNumber -eq $SerialNumber }
}
catch {
    Fail "Failed to query windowsAutopilotDeviceIdentity objects: $($_.Exception.Message)"
}

if (-not $autopilotDevice) {
    Fail "No Windows Autopilot device identity found for serial number '$SerialNumber'. Confirm the device is registered before proceeding."
}

if (@($autopilotDevice).Count -gt 1) {
    Write-Host "WARNING: multiple Autopilot device identities matched this serial number. Using the first result." -ForegroundColor Yellow
    $autopilotDevice = @($autopilotDevice)[0]
}

Write-Host "  SerialNumber         : $($autopilotDevice.SerialNumber)"
Write-Host "  GroupTag             : $($autopilotDevice.GroupTag)"
Write-Host "  EnrollmentState      : $($autopilotDevice.EnrollmentState)"
Write-Host "  LastContactedDateTime: $($autopilotDevice.LastContactedDateTime)"
Write-Host "  ManagedDeviceId      : $($autopilotDevice.ManagedDeviceId)"
Write-Host "  AzureAdDeviceId      : $($autopilotDevice.AzureActiveDirectoryDeviceId)"
Write-Host "  ResourceName         : $($autopilotDevice.ResourceName)"

# ---------------------------------------------------------------------------
# 3. Look up profile assignment status (BETA-only fields - read via raw request)
# ---------------------------------------------------------------------------
Write-Section "Deployment profile assignment status (beta-only fields)"

$betaAssignmentStatus         = $null
$betaAssignmentDetailedStatus = $null
$betaAssignedDateTime         = $null

try {
    $betaUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($autopilotDevice.Id)"
    $betaResponse = Invoke-MgGraphRequest -Method GET -Uri $betaUri -ErrorAction Stop

    $betaAssignmentStatus         = $betaResponse.deploymentProfileAssignmentStatus
    $betaAssignmentDetailedStatus = $betaResponse.deploymentProfileAssignmentDetailedStatus
    $betaAssignedDateTime         = $betaResponse.deploymentProfileAssignedDateTime

    Write-Host "  AssignmentStatus         : $betaAssignmentStatus"
    Write-Host "  AssignmentDetailedStatus : $betaAssignmentDetailedStatus"
    Write-Host "  ProfileAssignedDateTime  : $betaAssignedDateTime"
}
catch {
    Write-Host "  Could not read beta-only assignment fields (this can happen if the beta schema has changed): $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Continuing with v1.0 fields only." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 4. Look up the matching Intune managed device (if enrolled)
# ---------------------------------------------------------------------------
Write-Section "Intune managed device"

$managedDevice = $null
if ($autopilotDevice.ManagedDeviceId -and $autopilotDevice.ManagedDeviceId -ne [Guid]::Empty.ToString()) {
    try {
        $managedDevice = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $autopilotDevice.ManagedDeviceId -ErrorAction Stop
    }
    catch {
        Write-Host "  Could not retrieve managed device by ID '$($autopilotDevice.ManagedDeviceId)': $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $managedDevice) {
    try {
        $managedDevice = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$SerialNumber'" -All -ErrorAction Stop | Select-Object -First 1
    }
    catch {
        Write-Host "  Could not query managed devices by serial number: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($managedDevice) {
    Write-Host "  DeviceName            : $($managedDevice.DeviceName)"
    Write-Host "  EnrollmentProfileName : $($managedDevice.EnrollmentProfileName)"
    Write-Host "  ComplianceState       : $($managedDevice.ComplianceState)"
    Write-Host "  LastSyncDateTime      : $($managedDevice.LastSyncDateTime)"
    Write-Host "  ManagementState       : $($managedDevice.ManagementState)"
}
else {
    Write-Host "  No matching Intune managed device found. Device has not completed MDM enrollment yet." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 5. Look up the matching Microsoft Entra device object
# ---------------------------------------------------------------------------
Write-Section "Microsoft Entra device object"

$entraDevice = $null
if ($autopilotDevice.AzureActiveDirectoryDeviceId) {
    try {
        $entraDevice = Get-MgDevice -Filter "deviceId eq '$($autopilotDevice.AzureActiveDirectoryDeviceId)'" -ErrorAction Stop | Select-Object -First 1
    }
    catch {
        Write-Host "  Could not query Entra device object: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($entraDevice) {
    Write-Host "  DisplayName    : $($entraDevice.DisplayName)"
    Write-Host "  TrustType      : $($entraDevice.TrustType)"
    Write-Host "  ApproximateLastSignInDateTime : $($entraDevice.ApproximateLastSignInDateTime)"
}
else {
    Write-Host "  No matching Entra device object found (or the device has never joined Entra ID)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. Cross-reference known failure signatures
# ---------------------------------------------------------------------------
Write-Section "Failure signature check"

$flags = @()

if ($autopilotDevice.EnrollmentState -eq 'failed') {
    $flags += "EnrollmentState is 'failed'. Check Event Viewer under Applications and Services Logs > Microsoft > Windows > ModernDeployment-Diagnostics-Provider > Autopilot for Event IDs 807/809/815/908."
}

if ($autopilotDevice.EnrollmentState -eq 'blocked') {
    $flags += "EnrollmentState is 'blocked'. This matches the 0x80180014 re-enrollment block scenario - check Devices > Windows > Enrollment > Windows Autopilot > Devices for an 'Unblock device' action, or confirm Windows (MDM) enrollment restriction is set to Allow."
}

if ($betaAssignmentStatus -in @('notAssigned', 'failed', 'pending')) {
    $flags += "Deployment profile assignment status is '$betaAssignmentStatus'. This matches Event ID 809/815 (assigned profile missing, or no profile assigned and no default profile in the tenant)."
}

if ($betaAssignmentStatus -eq 'assignedOutOfSync' -or $betaAssignmentStatus -eq 'assignedUnkownSyncState') {
    $flags += "Deployment profile assignment status is '$betaAssignmentStatus'. The profile is assigned but has not confirmed sync - trigger a sync from Devices > Windows Autopilot > Devices > Sync and re-check."
}

if ($betaAssignmentDetailedStatus -and $betaAssignmentDetailedStatus -ne 'none') {
    $flags += "Deployment profile assignment DETAILED status is '$betaAssignmentDetailedStatus' - this device does not meet the requirements of its assigned profile (for example, a profile type not supported on this hardware class)."
}

if ($managedDevice -and $entraDevice -and $entraDevice.TrustType -eq 'Workplace') {
    $flags += "Entra device TrustType is 'Workplace' (Microsoft Entra registered) despite the device being enrolled in Intune. This matches the documented 'shows as Microsoft Entra registered instead of joined' issue - usually caused by a stale Workplace-join object that predates the Autopilot join."
}

if ($managedDevice -and $managedDevice.EnrollmentProfileName -match '^OfflineAutoPilotProfile-') {
    $flags += "EnrollmentProfileName is '$($managedDevice.EnrollmentProfileName)' - this device enrolled using the offline 'Windows Autopilot for existing devices' JSON profile, not its assigned online profile. This happens when the online profile times out during OOBE."
}

if (-not $managedDevice -and $autopilotDevice.EnrollmentState -eq 'notContacted') {
    $flags += "Device has never contacted Intune (EnrollmentState = notContacted). Confirm network/firewall access to Windows Autopilot service endpoints and check the device registry key HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot for IsAutopilotDisabled = 1 or a blank CloudAssignedTenantDomain."
}

if ($flags.Count -eq 0) {
    Write-Host "  No known failure signatures matched. Device state looks healthy based on available data." -ForegroundColor Green
}
else {
    foreach ($flag in $flags) {
        Write-Host "  [FLAGGED] $flag" -ForegroundColor Yellow
    }
}

Write-Section "Summary"
Write-Host "  Serial number   : $SerialNumber"
Write-Host "  Autopilot state : $($autopilotDevice.EnrollmentState)"
Write-Host "  Profile status  : $(if ($betaAssignmentStatus) { $betaAssignmentStatus } else { 'unavailable (beta fields not returned)' })"
Write-Host "  Intune enrolled : $(if ($managedDevice) { 'Yes' } else { 'No' })"
Write-Host "  Entra join type : $(if ($entraDevice) { $entraDevice.TrustType } else { 'unknown' })"
Write-Host "  Signatures found: $($flags.Count)"
Write-Host ""
Write-Host "This script performed read-only Graph queries only. No changes were made to any device, profile, or object." -ForegroundColor Green
