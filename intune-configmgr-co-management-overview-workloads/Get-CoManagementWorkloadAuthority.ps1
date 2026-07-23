#Requires -Modules Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Reports Configuration Manager + Intune co-management state and workload authority
    signals for one or more managed Windows devices, via Microsoft Graph.

.DESCRIPTION
    Get-CoManagementWorkloadAuthority.ps1 is a READ-ONLY reporting script. It connects to
    Microsoft Graph, queries managedDevice records, and reports:

      - Whether a device is genuinely co-managed at all (managementAgent /
        deviceEnrollmentType), as opposed to Intune-only or ConfigMgr-only.
      - The configurationManagerClientEnabledFeatures flags Graph exposes for each
        co-managed device (inventory, modernApps, resourceAccess, deviceConfiguration,
        compliancePolicy, windowsUpdateForBusiness).

    IMPORTANT — read before treating this as an authoritative workload-authority report:
    Microsoft's public Graph reference for configurationManagerClientEnabledFeatures does
    not document, in plain language, whether "true" means "this feature is still enabled on
    the ConfigMgr client side" (i.e. NOT yet switched to Intune) or something else, and the
    six flags do not map one-to-one onto all seven co-management workloads visible in the
    ConfigMgr console (there is no distinct flag for Endpoint Protection or Office
    Click-to-Run apps as separate items). This script surfaces the raw flags AS REPORTED BY
    GRAPH and labels them accordingly — it does NOT assert a definitive mapping to the
    ConfigMgr console's per-workload sliders. For an authoritative answer on a specific
    device, cross-check against the ConfigMgr console's co-management dashboard or the
    client-side CoManagementHandler WMI class (root\ccm\CoManagementHandler,
    CoManagementFlags class) on the device itself.

    This script makes NO configuration changes anywhere. It only calls read (GET) Graph
    cmdlets. If Graph returns an error for any reason, the script fails loudly (exit 1)
    rather than silently returning partial or empty results.

.PARAMETER DeviceName
    One or more Intune managed device names to report on (matches Graph deviceName).
    If omitted, and -All is not specified, the script prompts for at least one filter.

.PARAMETER SerialNumber
    One or more device serial numbers to report on instead of device name.

.PARAMETER All
    Report on every managed Windows device in the tenant. Can return a large result set —
    use with -OutputPath to export to CSV rather than flooding the console.

.PARAMETER OutputPath
    Optional path to export results as CSV in addition to console output.

.EXAMPLE
    .\Get-CoManagementWorkloadAuthority.ps1 -DeviceName "DESKTOP-ABC123"

    Reports co-management state for a single named device.

.EXAMPLE
    .\Get-CoManagementWorkloadAuthority.ps1 -All -OutputPath "C:\Reports\comgmt-state.csv"

    Reports co-management state for every managed Windows device in the tenant and also
    writes the results to CSV.

.EXAMPLE
    .\Get-CoManagementWorkloadAuthority.ps1 -SerialNumber "PF3ABC12","PF3ABC13"

    Reports co-management state for two devices identified by serial number.

.NOTES
    Author        : Imran Awan
    Blog          : https://endpointweekly.com/blog/intune-configmgr-co-management-overview-workloads.html
    Read-only     : Yes — calls Get-MgDeviceManagementManagedDevice (GET) only. No writes.
    Requires      : Microsoft.Graph.DeviceManagement module, DeviceManagementManagedDevices.Read.All scope.
    Tested against: real output pending — will be added once tested against a live tenant.
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string[]]$DeviceName,

    [Parameter(ParameterSetName = 'BySerial')]
    [string[]]$SerialNumber,

    [Parameter(ParameterSetName = 'All')]
    [switch]$All,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Write-FailAndExit {
    param([string]$Message)
    Write-Error $Message
    exit 1
}

if (-not $DeviceName -and -not $SerialNumber -and -not $All) {
    Write-FailAndExit "No target specified. Provide -DeviceName, -SerialNumber, or -All."
}

# --- Connect to Microsoft Graph (delegated auth, read-only scope) ---------------------
try {
    $requiredScope = 'DeviceManagementManagedDevices.Read.All'
    $context = Get-MgContext -ErrorAction SilentlyContinue

    if (-not $context -or $context.Scopes -notcontains $requiredScope) {
        Connect-MgGraph -Scopes $requiredScope -NoWelcome
        $context = Get-MgContext
    }

    if (-not $context) {
        Write-FailAndExit "Unable to establish a Microsoft Graph session. Aborting."
    }

    Write-Verbose "Connected to Microsoft Graph as $($context.Account) with scopes: $($context.Scopes -join ', ')"
}
catch {
    Write-FailAndExit "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

# --- Build the device set to report on -------------------------------------------------
$devices = @()

try {
    if ($All) {
        Write-Verbose "Retrieving all managed Windows devices from Graph..."
        $devices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'" -All -ErrorAction Stop
    }
    elseif ($DeviceName) {
        foreach ($name in $DeviceName) {
            Write-Verbose "Looking up device by name: $name"
            $match = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$name'" -ErrorAction Stop
            if (-not $match) {
                Write-Warning "No managed device found matching deviceName '$name'."
            }
            $devices += $match
        }
    }
    elseif ($SerialNumber) {
        foreach ($serial in $SerialNumber) {
            Write-Verbose "Looking up device by serial number: $serial"
            # Server-side $filter on serialNumber has been unreliable for some tenants/API
            # versions in the past — pull candidates broadly then filter client-side to be safe.
            $candidates = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop |
                Where-Object { $_.SerialNumber -eq $serial }
            if (-not $candidates) {
                Write-Warning "No managed device found matching serial number '$serial'."
            }
            $devices += $candidates
        }
    }
}
catch {
    Write-FailAndExit "Microsoft Graph query failed: $($_.Exception.Message)"
}

if (-not $devices -or $devices.Count -eq 0) {
    Write-FailAndExit "No matching managed devices were returned by Microsoft Graph. Nothing to report."
}

# --- Co-managed management agent values (both ConfigMgr client + Intune MDM active) ---
$coManagedAgentValues = @('configurationManagerClientMdm', 'configurationManagerClientMdmEas')

# --- Build the report --------------------------------------------------------------------
$report = foreach ($device in $devices) {

    $isCoManaged = $device.ManagementAgent -in $coManagedAgentValues
    $features    = $device.ConfigurationManagerClientEnabledFeatures

    [PSCustomObject]@{
        DeviceName                       = $device.DeviceName
        SerialNumber                     = $device.SerialNumber
        ManagementAgent                  = $device.ManagementAgent
        DeviceEnrollmentType             = $device.DeviceEnrollmentType
        IsCoManaged                      = $isCoManaged
        CM_Inventory                     = if ($isCoManaged -and $features) { $features.Inventory } else { 'N/A - not co-managed' }
        CM_ModernApps                    = if ($isCoManaged -and $features) { $features.ModernApps } else { 'N/A - not co-managed' }
        CM_ResourceAccess                = if ($isCoManaged -and $features) { $features.ResourceAccess } else { 'N/A - not co-managed' }
        CM_DeviceConfiguration           = if ($isCoManaged -and $features) { $features.DeviceConfiguration } else { 'N/A - not co-managed' }
        CM_CompliancePolicy              = if ($isCoManaged -and $features) { $features.CompliancePolicy } else { 'N/A - not co-managed' }
        CM_WindowsUpdateForBusiness       = if ($isCoManaged -and $features) { $features.WindowsUpdateForBusiness } else { 'N/A - not co-managed' }
        LastSyncDateTime                 = $device.LastSyncDateTime
        InterpretationCaveat             = 'CM_* flags reflect Graph configurationManagerClientEnabledFeatures as reported. Microsoft does not document a definitive true/false-to-workload-slider mapping. Cross-check against the ConfigMgr console co-management dashboard or client-side CoManagementHandler WMI class before acting on this report.'
    }
}

# --- Output --------------------------------------------------------------------------
$report | Format-Table DeviceName, SerialNumber, ManagementAgent, IsCoManaged, CM_DeviceConfiguration, CM_CompliancePolicy, CM_WindowsUpdateForBusiness -AutoSize

if ($OutputPath) {
    try {
        $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-FailAndExit "Failed to export report to '$OutputPath': $($_.Exception.Message)"
    }
}

Write-Host "`nReminder: this script is read-only. It reports state, it does not switch workload authority." -ForegroundColor Yellow
