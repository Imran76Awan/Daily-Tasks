<#
.SYNOPSIS
    Read-only Microsoft Graph audit of Endpoint Privilege Management (EPM) deployment readiness.

.DESCRIPTION
    Reports on the current state of Intune Endpoint Privilege Management (EPM) in a tenant:

      1. Lists every Settings Catalog-style configuration policy whose "technologies" flag
         includes 'endpointPrivilegeManagement' (this covers both Windows elevation settings
         policies and Windows elevation rules policies - both policy types are delivered
         through the same /deviceManagement/configurationPolicies Graph endpoint), together
         with the Entra ID group(s) each policy is assigned to.
      2. Lists pending EPM support-approved elevation requests (/deviceManagement/elevationRequests)
         so an admin can see how many requests are waiting for review without opening the
         Intune admin center.
      3. Summarizes recent elevation activity (/deviceManagement/privilegeManagementElevations)
         over a lookback window, broken down by elevation type (unmanaged, zero-touch/automatic,
         user-confirmed, support-approved). This is the same signal the EPM Overview readiness
         dashboard in the Intune admin center is built from - "users with only unmanaged
         elevations" is exactly the unmanagedElevation count this script reports per user.

    This script makes NO changes to the tenant. It only issues HTTP GET requests through
    Invoke-MgGraphRequest. It never calls a Set/New/Remove/Update/Add/Disable/Enable/Invoke
    cmdlet, and it never approves, denies, or otherwise touches an elevation request.

    Tenant licensing for EPM cannot be confirmed with certainty from Graph alone (there is no
    single "IsEpmLicensed" flag). Section 1 of the output lists the tenant's subscribed SKUs
    so an admin can visually confirm Microsoft 365 E5, the standalone EPM add-on, or the
    Intune Suite is present - this script does not guess or hard-code specific SKU GUIDs,
    because those change over time and per-region and a wrong guess would be worse than no
    guess at all.

.NOTES
    Blog post : https://endpointweekly.com/blog/intune-endpoint-privilege-management-2026-deployment-guide.html
    Author    : EndpointWeekly / Imran Awan
    Requires  : Microsoft.Graph.Authentication module (Connect-MgGraph / Invoke-MgGraphRequest)
    Read-only : Yes. GET requests only. No tenant state is modified.
    Exit codes: 0 = report completed successfully
                1 = connection, authentication, or Graph query error

.EXAMPLE
    .\Get-EPMDeploymentReadinessReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "<app-id>" -CertificateThumbprint "<thumbprint>"

    Runs the report using app-only (certificate) authentication - the recommended method for
    a scheduled or unattended run.

.EXAMPLE
    .\Get-EPMDeploymentReadinessReport.ps1 -UseDeviceCode -LookbackDays 14 -CsvPath C:\Reports\epm-readiness.csv

    Runs the report interactively using device code sign-in, widens the elevation activity
    lookback window to 14 days, and exports the policy-assignment and activity-summary tables
    to CSV.
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
    [ValidateRange(1, 90)]
    [int]$LookbackDays = 7,

    [Parameter()]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor DarkGray
}

function Get-AllGraphPages {
    # Follows @odata.nextLink until every page of a Graph collection has been retrieved.
    # GET only - never used against a write endpoint in this script.
    param([Parameter(Mandatory = $true)][string]$Uri)

    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    while ($null -ne $nextUri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        }
        catch {
            Write-Warning "Graph GET failed for '$nextUri': $($_.Exception.Message)"
            $script:hadError = $true
            return $results
        }
        if ($response.value) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        $nextUri = $response.'@odata.nextLink'
    }
    return $results
}

# --- Connect ------------------------------------------------------------------------------

Write-Section "Connecting to Microsoft Graph (read-only)"

try {
    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome
        Write-Host "Connected using app-only certificate authentication." -ForegroundColor Green
    }
    else {
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All", "Directory.Read.All" `
            -UseDeviceCode -NoWelcome
        Write-Host "Connected using delegated device code sign-in." -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# --- Section 1: tenant licensing signal (informational only, no SKU IDs hard-coded) ------

Write-Section "1. Tenant subscribed SKUs (confirm E5 / Intune Suite / EPM add-on manually)"

$skus = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
if ($skus.Count -eq 0) {
    Write-Host "No subscribed SKUs returned, or the call failed above." -ForegroundColor Yellow
}
else {
    $skus |
        Select-Object skuPartNumber, @{n = 'Enabled'; e = { $_.prepaidUnits.enabled } }, @{n = 'Consumed'; e = { $_.consumedUnits } } |
        Sort-Object skuPartNumber |
        Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Cross-check the skuPartNumber values above against your own tenant's licensing" -ForegroundColor DarkGray
    Write-Host "portal (M365 admin center > Billing > Licenses) to confirm EPM entitlement -" -ForegroundColor DarkGray
    Write-Host "this script deliberately does not assume which SKU string means 'EPM licensed'." -ForegroundColor DarkGray
}

# --- Section 2: EPM policies (elevation settings + elevation rules) and their assignments -

Write-Section "2. EPM configuration policies and group assignments"

$allPolicies = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,technologies,templateReference"

$epmPolicies = $allPolicies | Where-Object {
    $_.technologies -and ($_.technologies -split ',') -contains 'endpointPrivilegeManagement'
}

if ($epmPolicies.Count -eq 0) {
    Write-Host "No EPM elevation settings or elevation rules policies were found in this tenant." -ForegroundColor Yellow
    Write-Host "If you expected EPM policies to exist, confirm the account used to run this" -ForegroundColor Yellow
    Write-Host "script holds DeviceManagementConfiguration.Read.All (or ReadWrite.All)." -ForegroundColor Yellow
}

$policyReport = New-Object System.Collections.Generic.List[object]

foreach ($policy in $epmPolicies) {
    $groupNames = New-Object System.Collections.Generic.List[string]

    $assignments = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policy.id)/assignments"

    foreach ($assignment in $assignments) {
        $target = $assignment.target
        switch ($target.'@odata.type') {
            '#microsoft.graph.allLicensedUsersAssignmentTarget' { $groupNames.Add('All users') }
            '#microsoft.graph.allDevicesAssignmentTarget'       { $groupNames.Add('All devices') }
            default {
                $groupId = $target.groupId
                if ($groupId) {
                    try {
                        $group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($groupId)?`$select=displayName"
                        $groupNames.Add($group.displayName)
                    }
                    catch {
                        $groupNames.Add("Unresolved group ($groupId)")
                        $script:hadError = $true
                    }
                }
            }
        }
    }

    $policyReport.Add([PSCustomObject]@{
        PolicyName      = $policy.name
        PolicyType      = $policy.templateReference.templateDisplayName
        AssignedGroups  = if ($groupNames.Count -gt 0) { ($groupNames -join '; ') } else { '(not assigned)' }
    })
}

if ($policyReport.Count -gt 0) {
    $policyReport | Format-Table -AutoSize -Wrap | Out-String | Write-Host
}

# --- Section 3: pending support-approved elevation requests -------------------------------

Write-Section "3. Pending support-approved elevation requests"

$requests = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/elevationRequests?`$filter=status eq 'pending'"

if ($requests.Count -eq 0) {
    Write-Host "No pending elevation requests." -ForegroundColor Green
}
else {
    Write-Host "$($requests.Count) request(s) waiting for admin review:" -ForegroundColor Yellow
    $requests |
        Select-Object deviceName, requestedByUserPrincipalName, `
            @{n = 'File'; e = { $_.applicationDetail.fileName } }, `
            requestCreatedDateTime, requestJustification |
        Sort-Object requestCreatedDateTime |
        Format-Table -AutoSize -Wrap | Out-String | Write-Host
}

# --- Section 4: recent elevation activity summary (mirrors the Overview dashboard) --------

Write-Section "4. Elevation activity summary - last $LookbackDays day(s)"

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$elevations = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/privilegeManagementElevations?`$filter=eventDateTime ge $cutoff"

if ($elevations.Count -eq 0) {
    Write-Host "No elevation events reported in the lookback window (or reporting scope is limited)." -ForegroundColor Yellow
}
else {
    $byType = $elevations | Group-Object elevationType | Sort-Object Count -Descending
    $byType | Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host

    $unmanagedUsers = $elevations |
        Where-Object { $_.elevationType -eq 'unmanagedElevation' } |
        Select-Object -ExpandProperty upn -Unique

    if ($unmanagedUsers.Count -gt 0) {
        Write-Host "Users with at least one UNMANAGED elevation in this window (candidates for a new rule):" -ForegroundColor Yellow
        $unmanagedUsers | ForEach-Object { Write-Host "  - $_" }
    }
}

# --- Optional CSV export --------------------------------------------------------------------

if ($CsvPath) {
    try {
        $policyReport | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "Policy/assignment table exported to $CsvPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to write CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

Write-Section "Done"

if ($script:hadError) {
    Write-Warning "One or more Graph queries failed during this run - review the warnings above."
    exit 1
}

exit 0
