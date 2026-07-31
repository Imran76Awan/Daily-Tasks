#Requires -Version 5.1
<#
.SYNOPSIS
    Reports Intune configuration profiles, compliance policies and apps that are
    scoped only to the built-in Default scope tag (or have no scope tag at all) and
    are therefore visible to every scoped admin whose role assignment carries Default.

.DESCRIPTION
    Intune RBAC scope tags decide which objects an admin can see. Scope tags only ADD
    visibility: an object is visible to an admin when the object and the admin's role
    assignment share at least one scope tag. Any object nobody explicitly tags is
    automatically assigned the built-in Default scope tag (id "0"), so it stays visible
    to every admin whose role assignment includes Default (which is nearly all of them).
    That is a silent visibility leak: a "scoped" admin can still see and, with write
    permissions, edit every untagged object in the tenant.

    This script is REPORT-ONLY. It performs GET requests against Microsoft Graph (beta)
    to:
      1. Resolve the built-in Default scope tag (isBuiltIn = true; id is "0").
      2. Enumerate device configuration profiles, device compliance policies and
         mobile apps, reading each object's roleScopeTagIds property.
      3. Flag every object whose scope-tag set is empty or contains only the Default
         tag, and summarise how many objects fall outside intended scope-tag coverage.

    It never creates, edits, assigns, removes, enables, disables or deletes a scope
    tag, a policy, an app or a role assignment. Nothing is changed anywhere. Assigning
    real scope tags to the objects it finds is a deliberate manual decision you make
    afterwards.

    Least-privilege READ scopes used:
      - DeviceManagementRBAC.Read.All          (list role scope tags)
      - DeviceManagementConfiguration.Read.All (configuration profiles + compliance policies)
      - DeviceManagementApps.Read.All          (mobile apps)
    No ReadWrite scope is ever requested.

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication. Use together with
    -ClientId and -CertificateThumbprint for unattended runs.

.PARAMETER ClientId
    Application (client) ID of the app registration for app-only certificate auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate (in the local certificate store) used for
    app-only certificate auth.

.PARAMETER UseDeviceCode
    Interactive fallback. Signs in with the device-code flow instead of app-only
    certificate auth. Useful for a one-off run from an admin workstation.

.PARAMETER ExportCsv
    When set, writes the flagged objects (and their scope tags) to a CSV file.

.PARAMETER CsvPath
    Optional path for the CSV export. Defaults to a timestamped file in the current
    directory. Implies -ExportCsv when supplied.

.EXAMPLE
    .\Get-ScopeTagCoverageReport.ps1 -UseDeviceCode
    Interactive run using the device-code sign-in flow.

.EXAMPLE
    .\Get-ScopeTagCoverageReport.ps1 -TenantId "<guid>" -ClientId "<guid>" -CertificateThumbprint "<thumb>"
    Unattended run using app-only certificate authentication.

.EXAMPLE
    .\Get-ScopeTagCoverageReport.ps1 -UseDeviceCode -ExportCsv -CsvPath "C:\Reports\ScopeTagCoverage.csv"
    Interactive run that also exports the flagged objects to a CSV file.

.NOTES
    Author  : Imran Awan (EndpointWeekly)
    Requires: Microsoft.Graph.Authentication module (Connect-MgGraph / Invoke-MgGraphRequest).
    Exit codes:
      0 = clean. No objects are scoped only to Default (or untagged).
      1 = script or Graph query error. Do not trust the results.
      2 = findings. One or more objects are scoped only to Default (or untagged).
    Read-only. It never changes any Intune object. Uses Graph beta endpoints because
    roleScopeTagIds is fully populated there for all three object types.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
    [switch] $UseDeviceCode,

    [Parameter()]
    [switch] $ExportCsv,

    [Parameter()]
    [string] $CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:hadError = $false

$GraphBase = 'https://graph.microsoft.com/beta'
$ReadScopes = @(
    'DeviceManagementRBAC.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All'
)

function Write-Section {
    param([string] $Text)
    Write-Host ''
    Write-Host ('=' * 64)
    Write-Host ("  " + $Text)
    Write-Host ('=' * 64)
}

function Invoke-GraphGetAll {
    # Pages through a Graph collection endpoint and returns all items.
    # Throws on failure so the caller can fail loud.
    param([Parameter(Mandatory = $true)][string] $Uri)

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next
        if ($null -ne $response.value) {
            foreach ($v in $response.value) { [void]$items.Add($v) }
        }
        if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $next = $response.'@odata.nextLink'
        }
        else {
            $next = $null
        }
    }
    return $items
}

function Get-TagIdList {
    # Normalises the roleScopeTagIds property to a string array (may be missing/empty).
    param($Object)
    if ($null -eq $Object) { return @() }
    if (-not ($Object.PSObject.Properties.Name -contains 'roleScopeTagIds')) { return @() }
    $ids = $Object.roleScopeTagIds
    if ($null -eq $ids) { return @() }
    return @($ids | ForEach-Object { [string]$_ })
}

function Test-OnlyDefaultTag {
    # True when the object leaks: no tags, or every tag is the Default tag.
    param([string[]] $TagIds, [string] $DefaultId)
    if (-not $TagIds -or $TagIds.Count -eq 0) { return $true }
    $nonDefault = @($TagIds | Where-Object { $_ -ne $DefaultId })
    return ($nonDefault.Count -eq 0)
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
try {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw "Microsoft.Graph.Authentication module not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }

    if ($PSCmdlet.ParameterSetName -eq 'DeviceCode') {
        Write-Host "Connecting to Microsoft Graph (device code)..."
        Connect-MgGraph -Scopes $ReadScopes -UseDeviceCode -NoWelcome | Out-Null
    }
    else {
        Write-Host "Connecting to Microsoft Graph (app-only certificate)..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome | Out-Null
    }

    $ctx = Get-MgContext
    if ($null -eq $ctx) { throw "Connect-MgGraph did not return a context." }
    Write-Host ("Connected. Tenant: " + $ctx.TenantId)
}
catch {
    $script:hadError = $true
    Write-Host ("[ERROR] Failed to connect to Microsoft Graph: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host "[ERROR] Cannot continue without a Graph connection. Exiting 1." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Resolve the built-in Default scope tag
# ---------------------------------------------------------------------------
$defaultId = $null
try {
    Write-Host "Resolving built-in Default scope tag..."
    $scopeTags = Invoke-GraphGetAll -Uri "$GraphBase/deviceManagement/roleScopeTags?`$select=id,displayName,isBuiltIn"
    $builtIn = @($scopeTags | Where-Object { $_.isBuiltIn -eq $true })
    if ($builtIn.Count -eq 0) {
        throw "No built-in (Default) scope tag was returned by Graph."
    }
    $defaultTag = $builtIn[0]
    $defaultId = [string]$defaultTag.id
    $customCount = ($scopeTags | Where-Object { $_.isBuiltIn -ne $true }).Count
    Write-Host ("  Default scope tag id : " + $defaultId + "  (DisplayName '" + $defaultTag.displayName + "', IsBuiltIn True)")
    Write-Host ("  Custom scope tags     : " + $customCount)
}
catch {
    $script:hadError = $true
    Write-Host ("[ERROR] Failed to read role scope tags: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host "[ERROR] Cannot classify objects without the Default tag id. Exiting 1." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Enumerate objects that support scope tags
# ---------------------------------------------------------------------------
# Endpoints verified to expose roleScopeTagIds. Extend with configurationPolicies
# (Settings Catalog) and deviceHealthScripts using the same pattern if required.
$targets = @(
    [pscustomobject]@{ Type = 'deviceConfiguration'; NameField = 'displayName'; Uri = "$GraphBase/deviceManagement/deviceConfigurations?`$select=id,displayName,roleScopeTagIds" }
    [pscustomobject]@{ Type = 'compliancePolicy';    NameField = 'displayName'; Uri = "$GraphBase/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,roleScopeTagIds" }
    [pscustomobject]@{ Type = 'mobileApp';           NameField = 'displayName'; Uri = "$GraphBase/deviceAppManagement/mobileApps?`$select=id,displayName,roleScopeTagIds" }
)

$allObjects = New-Object System.Collections.Generic.List[object]
$scanned = 0

Write-Host ''
Write-Host "Enumerating objects and reading roleScopeTagIds..."
foreach ($t in $targets) {
    try {
        $objs = Invoke-GraphGetAll -Uri $t.Uri
        foreach ($o in $objs) {
            $tagIds = Get-TagIdList -Object $o
            $name = if ($o.PSObject.Properties.Name -contains $t.NameField) { [string]$o.($t.NameField) } else { '' }
            [void]$allObjects.Add([pscustomobject]@{
                ObjectType      = $t.Type
                DisplayName     = $name
                Id              = [string]$o.id
                RoleScopeTagIds = $tagIds
                LeaksToDefault  = (Test-OnlyDefaultTag -TagIds $tagIds -DefaultId $defaultId)
            })
        }
        $scanned += $objs.Count
        Write-Host ("  {0,-30} : {1}" -f $t.Type, $objs.Count)
    }
    catch {
        $script:hadError = $true
        Write-Host ("[ERROR] Failed to enumerate '" + $t.Type + "': " + $_.Exception.Message) -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Fail loud: never report a clean result after a failed query
# ---------------------------------------------------------------------------
if ($script:hadError) {
    Write-Host ''
    Write-Host "[ERROR] One or more Graph queries failed. Results are incomplete and" -ForegroundColor Red
    Write-Host "[ERROR] must not be trusted. Not printing a coverage summary. Exiting 1." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$leaks = @($allObjects | Where-Object { $_.LeaksToDefault })
$onlyDefault = @($leaks | Where-Object { $_.RoleScopeTagIds.Count -gt 0 })
$noTag = @($leaks | Where-Object { $_.RoleScopeTagIds.Count -eq 0 })
$withCustom = $scanned - $leaks.Count
$coverage = if ($scanned -gt 0) { [math]::Round((($withCustom / $scanned) * 100), 1) } else { 0 }

Write-Section -Text ("SCOPE TAG COVERAGE REPORT - " + (Get-Date -Format 'dd MMM yyyy HH:mm'))
Write-Host ("  Objects with a custom scope tag        : " + $withCustom)
Write-Host ("  Objects visible to ALL scoped admins   : " + $leaks.Count)
Write-Host ("     - only Default tag  : " + $onlyDefault.Count)
Write-Host ("     - no tag at all     : " + $noTag.Count)
Write-Host ('  ' + ('-' * 62))
Write-Host ("  Custom-tag coverage                     : " + $coverage + "%")
Write-Host ('=' * 64)

if ($leaks.Count -gt 0) {
    Write-Host ''
    Write-Host "Objects scoped only to Default (visible to every Default-scoped admin):"
    $view = $leaks | ForEach-Object {
        $tagText = if ($_.RoleScopeTagIds.Count -eq 0) { '(none)' } else { ($_.RoleScopeTagIds -join ',') }
        [pscustomobject]@{
            ObjectType      = $_.ObjectType
            DisplayName     = $_.DisplayName
            RoleScopeTagIds = $tagText
        }
    }
    $view | Format-Table -AutoSize | Out-Host
}

# ---------------------------------------------------------------------------
# Optional CSV export
# ---------------------------------------------------------------------------
if ($ExportCsv -or $PSBoundParameters.ContainsKey('CsvPath')) {
    try {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("ScopeTagCoverage_" + (Get-Date -Format 'yyyy-MM-dd_HHmm') + ".csv")
        }
        $export = $leaks | ForEach-Object {
            [pscustomobject]@{
                ObjectType      = $_.ObjectType
                DisplayName     = $_.DisplayName
                Id              = $_.Id
                RoleScopeTagIds = ($_.RoleScopeTagIds -join ';')
                Reason          = if ($_.RoleScopeTagIds.Count -eq 0) { 'NoTag' } else { 'OnlyDefault' }
            }
        }
        $export | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ("  CSV written: " + $CsvPath)
    }
    catch {
        # Reporting the findings succeeded; a CSV write failure is still an error.
        $script:hadError = $true
        Write-Host ("[ERROR] Failed to write CSV: " + $_.Exception.Message) -ForegroundColor Red
    }
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
if ($script:hadError) {
    Write-Host ''
    Write-Host "[ERROR] Completed with errors. Exiting 1." -ForegroundColor Red
    exit 1
}
elseif ($leaks.Count -gt 0) {
    Write-Host ''
    Write-Host ("FINDINGS: " + $leaks.Count + " object(s) scoped only to Default. Assign a real scope tag or") -ForegroundColor Yellow
    Write-Host "confirm each is intended to be tenant-wide, then re-run. Exit code: 2" -ForegroundColor Yellow
    exit 2
}
else {
    Write-Host ''
    Write-Host "CLEAN: every scanned object carries at least one custom scope tag. Exit code: 0" -ForegroundColor Green
    exit 0
}
