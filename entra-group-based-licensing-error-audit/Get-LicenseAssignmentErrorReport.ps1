#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Microsoft 365 / Entra ID license assignment errors that are hidden inside
    per-user licenseAssignmentStates - especially failures inherited from group-based
    (group) license assignment that the group and product views do not surface.

.DESCRIPTION
    When you assign licenses to a security group (group-based licensing), Entra ID
    processes the assignment per member. For some members the assignment can fail
    silently: a service-plan conflict, not enough available licenses, a service-plan
    dependency, a usage-location restriction, or a duplicate unique attribute such as
    a proxy address. The group assignment still shows as configured, and the failure
    only appears in each affected user's licenseAssignmentStates collection.

    This script connects to Microsoft Graph (read only), enumerates every user, and
    inspects each entry in the licenseAssignmentStates collection. It flags any entry
    whose 'state' is Error or ActiveWithError, or whose 'error' property is set to a
    documented failure value. For each flagged entry it resolves:

        - The SKU (product) from skuId via Get-MgSubscribedSku.
        - Whether the license is Direct or inherited from a Group (assignedByGroup),
          resolving the group's display name where possible.
        - The exact 'error' and 'state' values and the lastUpdatedDateTime timestamp.

    The documented licenseAssignmentState 'state' values are:
        Active, ActiveWithError, Disabled, Error
    The documented 'error' values are:
        CountViolation, MutuallyExclusiveViolation, DependencyViolation,
        ProhibitedInUsageLocationViolation, UniquenessViolation, Other
    (the 'error' property is null when the assignment succeeded).

    This script is REPORT-ONLY. It never creates, modifies, deletes, enables,
    disables, resets, reprocesses, or remediates any license, group, or user. Every
    Graph call is a read. If any Graph query fails, the script prints a clear error,
    sets an internal error flag, and exits with code 1 - it will NOT print a clean
    "no errors found" result after a failed query.

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the Entra app registration used for app-only
    certificate authentication.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (installed in the current user or local machine
    certificate store) used for app-only authentication.

.PARAMETER UseDeviceCode
    Use interactive device-code sign-in instead of app-only certificate auth. Useful
    for a quick run from a workstation. Requests the least-privilege read scopes:
    User.Read.All, Directory.Read.All, Organization.Read.All.

.PARAMETER ExportCsv
    Also write the flagged findings to a CSV file.

.PARAMETER CsvPath
    Destination path for the CSV export. Defaults to a timestamped file in the
    current directory. Only used when -ExportCsv is specified.

.EXAMPLE
    .\Get-LicenseAssignmentErrorReport.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumb>

    Runs unattended with app-only certificate auth and prints the report to the console.

.EXAMPLE
    .\Get-LicenseAssignmentErrorReport.ps1 -UseDeviceCode -ExportCsv

    Signs in interactively with device code, prints the report, and exports findings to CSV.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
              Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement
    Scopes  : User.Read.All, Directory.Read.All, Organization.Read.All (read only)
    Exit    : 0 = clean (no license errors found)
              1 = script or Graph query error (results not trustworthy)
              2 = license assignment errors detected

    This script is provided as-is with no warranty. Test before relying on output.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$ExportCsv,

    [Parameter()]
    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Internal state flags. $hadError is the fail-loud guard: if any Graph query fails
# this flips to $true and the script exits 1 instead of reporting a clean result.
$script:hadError = $false

# Least-privilege READ scopes for this task (device-code sign-in only).
$script:ReadScopes = @('User.Read.All', 'Directory.Read.All', 'Organization.Read.All')

# Documented failure signals we treat as findings.
$script:ErrorStates = @('Error', 'ActiveWithError')
$script:NonErrorValues = @($null, '', 'None')

function Write-Section {
    param([string]$Text)
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
}

function Test-GraphModule {
    # Confirm the required Graph command is available before we try to use it.
    if (-not (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue)) {
        Write-Host "[ERROR] Microsoft Graph PowerShell SDK not found." -ForegroundColor Red
        Write-Host "        Install it with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Red
        $script:hadError = $true
        return $false
    }
    return $true
}

function Connect-Graph {
    try {
        if ($UseDeviceCode) {
            Write-Host "Connecting to Microsoft Graph (device code, read-only scopes)..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $script:ReadScopes -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "Connecting to Microsoft Graph (app-only certificate auth)..." -ForegroundColor Cyan
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
                -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
        return $false
    }

    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($null -eq $ctx) {
            Write-Host "[ERROR] Connected but no Graph context was returned." -ForegroundColor Red
            $script:hadError = $true
            return $false
        }
        Write-Host "Connected. Tenant: $($ctx.TenantId)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Could not read Graph context: $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
        return $false
    }
}

function Get-SkuMap {
    # Map skuId -> skuPartNumber so the report shows product names, not GUIDs.
    $map = @{}
    try {
        $skus = Get-MgSubscribedSku -All -Property SkuId, SkuPartNumber -ErrorAction Stop
    }
    catch {
        Write-Host "[ERROR] Get-MgSubscribedSku failed: $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
        return $map
    }
    foreach ($sku in $skus) {
        if ($sku.SkuId -and -not $map.ContainsKey([string]$sku.SkuId)) {
            $map[[string]$sku.SkuId] = $sku.SkuPartNumber
        }
    }
    return $map
}

function Resolve-GroupName {
    param(
        [string]$GroupId,
        [hashtable]$Cache
    )
    if ([string]::IsNullOrEmpty($GroupId)) { return $null }
    if ($Cache.ContainsKey($GroupId)) { return $Cache[$GroupId] }

    try {
        $group = Get-MgGroup -GroupId $GroupId -Property DisplayName, Id -ErrorAction Stop
        $name = $group.DisplayName
        $Cache[$GroupId] = $name
        return $name
    }
    catch {
        # A missing group is itself meaningful: a deleted group leaves inherited
        # licenses in an error state. Record it, but do not treat NotFound as a
        # hard script failure. Any OTHER error is a real Graph problem -> fail loud.
        if ($_.Exception.Message -match 'not found|does not exist|Request_ResourceNotFound|NotFound') {
            $name = "(group not found - possibly deleted)"
            $Cache[$GroupId] = $name
            return $name
        }
        Write-Host "[ERROR] Get-MgGroup failed for $GroupId : $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
        $Cache[$GroupId] = "(group lookup failed)"
        return $Cache[$GroupId]
    }
}

function Test-IsErrorEntry {
    param($Entry)
    $stateBad = $script:ErrorStates -contains [string]$Entry.State
    $errVal = [string]$Entry.Error
    $errorBad = ($script:NonErrorValues -notcontains $Entry.Error) -and (-not [string]::IsNullOrEmpty($errVal))
    return ($stateBad -or $errorBad)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Section "ENTRA LICENSE ASSIGNMENT ERROR REPORT - $(Get-Date -Format 'dd MMM yyyy HH:mm')"

if (-not (Test-GraphModule)) {
    Write-Host "STATUS: SCRIPT ERROR - dependencies missing. Results not trustworthy." -ForegroundColor Red
    exit 1
}

if (-not (Connect-Graph)) {
    Write-Host "STATUS: SCRIPT ERROR - could not authenticate. Results not trustworthy." -ForegroundColor Red
    exit 1
}

$skuMap = Get-SkuMap
if ($script:hadError) {
    Write-Host "STATUS: SCRIPT ERROR - could not read subscribed SKUs. Results not trustworthy." -ForegroundColor Red
    exit 1
}

Write-Host "Enumerating users and inspecting licenseAssignmentStates..." -ForegroundColor Cyan

try {
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AssignedLicenses, LicenseAssignmentStates -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Get-MgUser failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "STATUS: SCRIPT ERROR - user enumeration failed. Results not trustworthy." -ForegroundColor Red
    exit 1
}

$groupCache = @{}
$findings = New-Object System.Collections.Generic.List[object]
$usersScanned = 0

foreach ($user in $users) {
    $usersScanned++

    $states = $user.LicenseAssignmentStates
    if (-not $states) { continue }

    foreach ($entry in $states) {
        if (-not (Test-IsErrorEntry -Entry $entry)) { continue }

        $skuId = [string]$entry.SkuId
        $skuName = if ($skuMap.ContainsKey($skuId)) { $skuMap[$skuId] } else { "(unknown or disabled SKU)" }

        if ([string]::IsNullOrEmpty([string]$entry.AssignedByGroup)) {
            $method = 'Direct'
            $groupName = ''
        }
        else {
            $method = 'Group'
            $groupName = Resolve-GroupName -GroupId ([string]$entry.AssignedByGroup) -Cache $groupCache
        }

        $errorValue = if ([string]::IsNullOrEmpty([string]$entry.Error)) { 'None' } else { [string]$entry.Error }

        $findings.Add([PSCustomObject]@{
            UserDisplayName   = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserId            = $user.Id
            SkuPartNumber     = $skuName
            SkuId             = $skuId
            AssignedBy        = $method
            GroupName         = $groupName
            GroupId           = [string]$entry.AssignedByGroup
            State             = [string]$entry.State
            Error             = $errorValue
            LastUpdated       = [string]$entry.LastUpdatedDateTime
        }) | Out-Null
    }
}

# Fail loud: if a group lookup or any read raised the flag mid-scan, do not present
# the numbers as complete or trustworthy.
if ($script:hadError) {
    Write-Host ""
    Write-Host "[ERROR] One or more Graph reads failed during the scan." -ForegroundColor Red
    Write-Host "STATUS: SCRIPT ERROR - partial data only. Results not trustworthy." -ForegroundColor Red
    exit 1
}

Write-Host "  Users scanned                 : $usersScanned" -ForegroundColor Gray
Write-Host "  License error entries found   : $($findings.Count)" -ForegroundColor Gray
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Section "RESULT"
    Write-Host "  No license assignment errors found across $usersScanned users." -ForegroundColor Green
    Write-Host "  STATUS: CLEAN" -ForegroundColor Green
    Write-Section "END"
    exit 0
}

Write-Section "LICENSE ASSIGNMENT ERRORS ($($findings.Count) found)"

foreach ($f in $findings) {
    $source = if ($f.AssignedBy -eq 'Group') { "Group: $($f.GroupName)" } else { 'Direct assignment' }
    Write-Host ""
    Write-Host "  User    : $($f.UserDisplayName) <$($f.UserPrincipalName)>" -ForegroundColor White
    Write-Host "  Product : $($f.SkuPartNumber)" -ForegroundColor White
    Write-Host "  Source  : $source" -ForegroundColor Yellow
    Write-Host "  State   : $($f.State)" -ForegroundColor Red
    Write-Host "  Error   : $($f.Error)" -ForegroundColor Red
    Write-Host "  Updated : $($f.LastUpdated)" -ForegroundColor Gray
}

$groupFindings = @($findings | Where-Object { $_.AssignedBy -eq 'Group' }).Count
$directFindings = @($findings | Where-Object { $_.AssignedBy -eq 'Direct' }).Count

Write-Host ""
Write-Section "SUMMARY"
Write-Host "  Total error entries      : $($findings.Count)" -ForegroundColor Red
Write-Host "  From group assignment    : $groupFindings" -ForegroundColor Yellow
Write-Host "  From direct assignment   : $directFindings" -ForegroundColor Yellow
Write-Section "END"

if ($ExportCsv) {
    if ([string]::IsNullOrEmpty($CsvPath)) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("LicenseAssignmentErrors_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
    }
    try {
        $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "CSV exported to: $CsvPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] CSV export failed: $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
    }
}

if ($script:hadError) {
    Write-Host "STATUS: SCRIPT ERROR during export. Results not trustworthy." -ForegroundColor Red
    exit 1
}

# Findings were detected.
exit 2
