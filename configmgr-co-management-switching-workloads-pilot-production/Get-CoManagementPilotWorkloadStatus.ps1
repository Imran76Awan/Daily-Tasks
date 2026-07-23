<#
.SYNOPSIS
    Reports which co-managed Windows devices belong to a pilot group versus everyone else,
    and the co-management / workload signals Microsoft Graph exposes for each device.

.DESCRIPTION
    Companion script for the EndpointWeekly post:
    https://endpointweekly.com/blog/configmgr-co-management-switching-workloads-pilot-production.html

    This script is READ-ONLY. It does not change any device, group, collection, or
    co-management workload setting. It only calls Microsoft Graph read (GET) endpoints.

    It answers two questions, using only what Microsoft Graph can actually see:

      1. Which devices are members of the Entra ID security group you specify with
         -PilotGroupId (or -PilotGroupName)? This is intended to be the same group that
         your ConfigMgr pilot collection's membership rule is built from — Configuration
         Manager supports creating a collection whose membership is sourced from an Entra ID
         (Azure AD) security group. If your pilot collection instead uses a query rule or
         direct/manual membership rule that is NOT backed by an Entra ID group, Graph has no
         way to see that membership at all, because ConfigMgr collections are a Configuration
         Manager site database construct with no Microsoft Graph endpoint. In that case this
         script will still run, but the "IsPilotGroupMember" column will only reflect Entra
         group membership, NOT true ConfigMgr collection membership — treat it as a proxy,
         not a direct read of the pilot collection, and confirm against the console.

      2. For every co-managed Windows device, what does Graph currently report for:
           - managementAgent (the device's overall enrollment/management channel — for a
             co-managed device this is typically one of: configurationManagerClient,
             configurationManagerClientMdm, configurationManagerClientMdmEas)
           - configurationManagerClientEnabledFeatures, a set of boolean flags Microsoft
             Graph documents on the managedDevice resource: inventory, modernApps,
             resourceAccess, deviceConfiguration, compliancePolicy, windowsUpdateForBusiness

    IMPORTANT / FLAGGED LIMITATION (do not treat this script as a full workload-authority
    report): the configurationManagerClientEnabledFeatures flags returned by Graph do not
    map 1:1 onto the seven co-management workload sliders you see in the ConfigMgr console
    (Compliance policies, Windows Update policies, Resource access policies, Endpoint
    Protection, Device configuration, Office Click-to-Run apps, Client apps). Notably, Graph
    has no dedicated "Endpoint Protection" or "Office Click-to-Run / Client apps" boolean in
    this structure, and it includes "inventory", which is not one of the seven switchable
    workloads at all. This script reports exactly what Graph returns, under the exact Graph
    property names, and does not infer or fabricate a workload it cannot see. For the
    authoritative, per-workload authority state, use the Workloads tab of the co-management
    properties in the Configuration Manager console.

.PARAMETER PilotGroupId
    The Object ID (GUID) of the Entra ID security group used as the source for your
    ConfigMgr pilot collection. Mutually exclusive with -PilotGroupName.

.PARAMETER PilotGroupName
    The display name of the Entra ID security group used as the source for your ConfigMgr
    pilot collection. The script resolves this to a group ID via Microsoft Graph. Mutually
    exclusive with -PilotGroupId. If more than one group matches this name, the script fails
    loudly rather than guessing which one you meant.

.PARAMETER OutputCsv
    Optional path to write the full report as CSV. If omitted, the report is written to the
    pipeline / host only.

.EXAMPLE
    .\Get-CoManagementPilotWorkloadStatus.ps1 -PilotGroupId "3f1a9c2e-1234-4a5b-9abc-1234567890ab"

    Reports co-management workload signals for every managed Windows device, flagging which
    ones are members of the specified pilot group.

.EXAMPLE
    .\Get-CoManagementPilotWorkloadStatus.ps1 -PilotGroupName "SG-ConfigMgr-Pilot-DeviceConfig" -OutputCsv ".\pilot-workload-status.csv"

    Resolves the pilot group by name, runs the same report, and also saves it to CSV.

.NOTES
    Blog post : https://endpointweekly.com/blog/configmgr-co-management-switching-workloads-pilot-production.html
    Author    : Imran Awan / EndpointWeekly
    Read-only : Yes. Uses only Get- (read) Microsoft Graph cmdlets. Never modifies devices,
                groups, collections, or co-management settings.
    Modules   : Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement,
                Microsoft.Graph.Groups
    Graph scopes required (delegated, read-only): DeviceManagementManagedDevices.Read.All,
                GroupMember.Read.All, Group.Read.All
    Behaviour : Fails loudly. Any authentication failure, missing module, unresolved group,
                or Graph API error causes the script to write a terminating error and exit
                with a non-zero exit code (exit 1). It never returns a partial or silently
                empty report as if it were a complete one.
#>

[CmdletBinding(DefaultParameterSetName = 'ById')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [ValidateNotNullOrEmpty()]
    [string]$PilotGroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [ValidateNotNullOrEmpty()]
    [string]$PilotGroupName,

    [Parameter(Mandatory = $false)]
    [string]$OutputCsv
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-FailAndExit {
    param([string]$Message, [System.Exception]$Exception)

    Write-Error "FATAL: $Message"
    if ($Exception) {
        Write-Error ("Details: {0}" -f $Exception.Message)
    }
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Confirm required modules are present. Fail loudly rather than trying
#    to auto-install anything — this script never modifies the host either.
# ---------------------------------------------------------------------------
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups'
)

foreach ($moduleName in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-FailAndExit "Required module '$moduleName' is not installed. Install it with: Install-Module $moduleName -Scope CurrentUser"
    }
}

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
}
catch {
    Write-FailAndExit "Failed to import one or more required Microsoft Graph modules." $_.Exception
}

# ---------------------------------------------------------------------------
# 2. Connect to Microsoft Graph with least-privilege, read-only scopes.
#    Same delegated-auth pattern used across other EndpointWeekly scripts.
# ---------------------------------------------------------------------------
$requiredScopes = @(
    'DeviceManagementManagedDevices.Read.All',
    'GroupMember.Read.All',
    'Group.Read.All'
)

try {
    $context = Get-MgContext
    if (-not $context -or ($requiredScopes | Where-Object { $_ -notin $context.Scopes })) {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
    }
}
catch {
    Write-FailAndExit "Could not authenticate to Microsoft Graph. Run Connect-MgGraph manually first if this keeps failing." $_.Exception
}

$context = Get-MgContext
if (-not $context) {
    Write-FailAndExit "Microsoft Graph session did not establish correctly after Connect-MgGraph." $null
}

Write-Host "Connected to Microsoft Graph as $($context.Account) (tenant: $($context.TenantId))." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Resolve the pilot group to a single, unambiguous group ID.
# ---------------------------------------------------------------------------
$resolvedGroupId = $null

try {
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $group = Get-MgGroup -GroupId $PilotGroupId -ErrorAction Stop
        $resolvedGroupId = $group.Id
        Write-Host "Pilot group resolved by ID: $($group.DisplayName) [$resolvedGroupId]" -ForegroundColor Cyan
    }
    else {
        $matchingGroups = @(Get-MgGroup -Filter "displayName eq '$PilotGroupName'" -ErrorAction Stop)
        if ($matchingGroups.Count -eq 0) {
            Write-FailAndExit "No Entra ID group found with display name '$PilotGroupName'. Cannot continue without a resolved pilot group." $null
        }
        elseif ($matchingGroups.Count -gt 1) {
            Write-FailAndExit "Found $($matchingGroups.Count) Entra ID groups named '$PilotGroupName'. Re-run with -PilotGroupId using the exact group Object ID to avoid ambiguity." $null
        }
        $resolvedGroupId = $matchingGroups[0].Id
        Write-Host "Pilot group resolved by name: $PilotGroupName [$resolvedGroupId]" -ForegroundColor Cyan
    }
}
catch {
    Write-FailAndExit "Failed to resolve the pilot group via Microsoft Graph." $_.Exception
}

# ---------------------------------------------------------------------------
# 4. Get pilot group membership (device object IDs only — we cross-reference
#    against managed devices by azureADDeviceId, which is the correct join key).
# ---------------------------------------------------------------------------
$pilotDeviceAadIds = New-Object System.Collections.Generic.HashSet[string]

try {
    $members = Get-MgGroupMember -GroupId $resolvedGroupId -All -ErrorAction Stop
    foreach ($member in $members) {
        if ($member.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.device') {
            $deviceId = $member.AdditionalProperties['deviceId']
            if ($deviceId) {
                [void]$pilotDeviceAadIds.Add($deviceId.ToString().ToLowerInvariant())
            }
        }
    }
}
catch {
    Write-FailAndExit "Failed to enumerate members of the pilot group. Check the GroupMember.Read.All scope was granted." $_.Exception
}

Write-Host "Pilot group contains $($pilotDeviceAadIds.Count) device object(s)." -ForegroundColor Cyan

if ($pilotDeviceAadIds.Count -eq 0) {
    Write-Warning "The pilot group has zero device members. Either the group genuinely has no device members yet, or it contains users/other groups instead of devices, or your ConfigMgr pilot collection is not actually backed by this Entra ID group. Continuing — the report will show every co-managed device as NOT in the pilot group."
}

# ---------------------------------------------------------------------------
# 5. Pull every managed Windows device and its co-management signals.
# ---------------------------------------------------------------------------
$selectProperties = @(
    'id',
    'deviceName',
    'azureADDeviceId',
    'operatingSystem',
    'managementAgent',
    'complianceState',
    'lastSyncDateTime',
    'configurationManagerClientEnabledFeatures'
) -join ','

try {
    $allDevices = Get-MgDeviceManagementManagedDevice -All -Property $selectProperties -ErrorAction Stop |
        Where-Object { $_.OperatingSystem -eq 'Windows' }
}
catch {
    Write-FailAndExit "Failed to retrieve managed devices from Microsoft Graph." $_.Exception
}

if (-not $allDevices -or $allDevices.Count -eq 0) {
    Write-FailAndExit "Get-MgDeviceManagementManagedDevice returned zero Windows devices. Refusing to write an empty report — check permissions and tenant data before assuming there really are no managed Windows devices." $null
}

# Co-managed devices are the ones whose managementAgent indicates the ConfigMgr
# client is present alongside MDM. Devices with any other managementAgent value
# are Intune-only or a different channel and are reported separately for context.
$coManagedAgentValues = @(
    'configurationManagerClient',
    'configurationManagerClientMdm',
    'configurationManagerClientMdmEas'
)

$report = foreach ($device in $allDevices) {
    $aadId = if ($device.AzureADDeviceId) { $device.AzureADDeviceId.ToString().ToLowerInvariant() } else { $null }
    $isPilotMember = $false
    if ($aadId -and $pilotDeviceAadIds.Contains($aadId)) {
        $isPilotMember = $true
    }

    $isCoManaged = $device.ManagementAgent -in $coManagedAgentValues

    $cmFeatures = $device.ConfigurationManagerClientEnabledFeatures

    [PSCustomObject]@{
        DeviceName                 = $device.DeviceName
        AzureADDeviceId            = $device.AzureADDeviceId
        IsPilotGroupMember         = $isPilotMember
        RolloutBucket              = if ($isPilotMember) { 'Pilot' } else { 'Production / Not in pilot group' }
        IsCoManaged                = $isCoManaged
        ManagementAgent            = $device.ManagementAgent
        ComplianceState            = $device.ComplianceState
        LastSyncDateTime           = $device.LastSyncDateTime
        CM_Inventory               = if ($cmFeatures) { $cmFeatures.Inventory } else { $null }
        CM_ModernApps              = if ($cmFeatures) { $cmFeatures.ModernApps } else { $null }
        CM_ResourceAccess          = if ($cmFeatures) { $cmFeatures.ResourceAccess } else { $null }
        CM_DeviceConfiguration     = if ($cmFeatures) { $cmFeatures.DeviceConfiguration } else { $null }
        CM_CompliancePolicy        = if ($cmFeatures) { $cmFeatures.CompliancePolicy } else { $null }
        CM_WindowsUpdateForBusiness = if ($cmFeatures) { $cmFeatures.WindowsUpdateForBusiness } else { $null }
    }
}

# ---------------------------------------------------------------------------
# 6. Output.
# ---------------------------------------------------------------------------
$report = $report | Sort-Object RolloutBucket, DeviceName

Write-Host ""
Write-Host "=== Co-management pilot vs production report ===" -ForegroundColor Yellow
Write-Host "Pilot group device count observed: $($pilotDeviceAadIds.Count)"
Write-Host "Total Windows managed devices evaluated: $($allDevices.Count)"
Write-Host "Co-managed (ConfigMgr client + MDM) devices found: $(($report | Where-Object IsCoManaged).Count)"
Write-Host ""

$report | Format-Table -AutoSize DeviceName, RolloutBucket, IsCoManaged, ManagementAgent, CM_DeviceConfiguration, CM_ResourceAccess, CM_CompliancePolicy

if ($OutputCsv) {
    try {
        $report | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Full report written to: $OutputCsv" -ForegroundColor Green
    }
    catch {
        Write-FailAndExit "Failed to write CSV output to '$OutputCsv'." $_.Exception
    }
}

Write-Host ""
Write-Host "Reminder: CM_* columns reflect only what Microsoft Graph's configurationManagerClientEnabledFeatures exposes." -ForegroundColor DarkYellow
Write-Host "They do not map 1:1 to the seven ConfigMgr co-management workload sliders. For the authoritative per-workload" -ForegroundColor DarkYellow
Write-Host "authority state (including Endpoint Protection, Office Click-to-Run apps, and Client apps), check the" -ForegroundColor DarkYellow
Write-Host "Workloads tab of the co-management properties in the Configuration Manager console." -ForegroundColor DarkYellow
