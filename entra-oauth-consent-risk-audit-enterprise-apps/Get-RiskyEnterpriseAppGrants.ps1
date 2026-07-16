<#
.SYNOPSIS
    Audits every Microsoft Entra ID enterprise application (service principal) in the tenant for
    high-risk Microsoft Graph permission grants combined with an unverified publisher status.

.DESCRIPTION
    Get-RiskyEnterpriseAppGrants.ps1 connects to Microsoft Graph and enumerates every enterprise
    application (service principal) in the tenant using Get-MgServicePrincipal -All. For each app it
    checks two separate consent surfaces:

      - APPLICATION permissions (app role assignments) — granted via Get-MgServicePrincipalAppRoleAssignment.
        These are the dangerous ones: an application permission gives the app its own standing identity
        in the tenant that can call Microsoft Graph with NO signed-in user present, 24 hours a day.
      - DELEGATED permissions (OAuth2 permission grants) — granted via Get-MgOauth2PermissionGrant.
        These only operate in the context of a signed-in user and are bounded by what that user can
        already do, but are still worth surfacing when they touch mailboxes or directory data at scale
        (e.g. Mail.ReadWrite granted tenant-wide rather than per-mailbox).

    Rather than hardcoding the GUIDs for each high-risk permission (which can be fragile if Microsoft
    ever changes them, and makes the script harder to audit by eye), this script resolves permission
    names to their GUIDs dynamically at runtime by reading the AppRoles and Oauth2PermissionScopes
    collections directly off the Microsoft Graph service principal object (appId
    00000003-0000-0000-c000-000000000000) in your own tenant. The $script:HighRiskPermissions hashtable
    is the single source of truth for which permission NAMES are considered high-risk — edit that list
    to match your organisation's own risk appetite.

    Risk scoring per enterprise application:

      RED   — holds one or more high-risk permissions AND has no verified publisher (VerifiedPublisher
              is null or has no DisplayName). This is the pattern described in the blog post: an
              unvetted vendor holding tenant-wide write access.
      AMBER — holds one or more high-risk permissions but DOES have a verified publisher. Still worth a
              business-justification review, but the publisher's identity has at least been confirmed
              by Microsoft's Partner Network verification process.
      GREEN — holds none of the permissions in the high-risk catalog.

    Microsoft first-party service principals (AppOwnerOrganizationId matching Microsoft's own services
    tenant) and the Microsoft Graph service principal itself are excluded from the results, since they
    are not third-party vendor apps.

    This script is READ-ONLY. It does not remove, modify, or create any permission grant. Remediation
    (revoking a permission) is a deliberate, manual step performed either through Entra ID > Enterprise
    applications > [app] > Permissions > Review permissions in the portal, or via the
    Remove-MgServicePrincipalAppRoleAssignment / Remove-MgOauth2PermissionGrant cmdlets run by hand
    after confirming business justification with the app owner. Example syntax for both is included as
    a comment near the bottom of this script for reference — it is NOT executed automatically.

.NOTES
    Author          : Imran Awan
    Blog post       : https://endpointweekly.com/blog/entra-oauth-consent-risk-audit-enterprise-apps.html
    Module required : Microsoft.Graph.Authentication, Microsoft.Graph.Applications
    Graph scopes    : Application.Read.All, Directory.Read.All
    Status          : NOT yet validated end-to-end against a production tenant. The cmdlet names,
                      property names, and the Microsoft Services tenant GUID used to exclude first-party
                      apps match the documented Microsoft Graph PowerShell SDK shape as of writing, but
                      you should dry-run this against a test/pilot tenant and review the output logic —
                      especially the high-risk permission catalog and the first-party exclusion filter —
                      before relying on it for an audit finding or compliance attestation. Report any
                      discrepancies back via the blog post comments so the script can be corrected.

.EXAMPLE
    .\Get-RiskyEnterpriseAppGrants.ps1

    Connects to Microsoft Graph interactively, audits every third-party enterprise application in the
    tenant, and prints a colour-coded (Green/Yellow/Red) report to the console. Only RED and AMBER
    findings are printed individually; GREEN apps are rolled up into the summary count.

.EXAMPLE
    .\Get-RiskyEnterpriseAppGrants.ps1 -ShowAllFindings

    Same as above, but also prints every GREEN (low-risk) enterprise application individually instead
    of just counting them — useful for a full point-in-time inventory rather than an exceptions report.

.EXAMPLE
    .\Get-RiskyEnterpriseAppGrants.ps1 -ExportCsv

    Runs the audit and additionally exports every application in the results (RED, AMBER, and GREEN) to
    a timestamped CSV file under C:\Reports\.

.EXAMPLE
    .\Get-RiskyEnterpriseAppGrants.ps1 -ExportCsv -CsvPath "C:\Temp\EnterpriseAppAudit.csv"

    Runs the audit and exports findings to a specific CSV path.

.EXAMPLE
    .\Get-RiskyEnterpriseAppGrants.ps1 -TenantId "contoso.onmicrosoft.com"

    Connects to a specific tenant by ID or verified domain before running the audit — useful for admins
    who manage more than one tenant.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "C:\Reports\EnterpriseAppRiskAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter(Mandatory = $false)]
    [switch]$ShowAllFindings
)

#region Configuration — the high-risk permission catalog
# This hashtable is the single source of truth for which Microsoft Graph permission NAMES are
# considered high-risk. Add or remove entries to match your own organisation's risk appetite. Names
# must match the "Value" property of the corresponding AppRole / Oauth2PermissionScope exactly as
# Microsoft Graph defines them — see https://learn.microsoft.com/en-us/graph/permissions-reference
$script:HighRiskPermissions = @{
    'Directory.ReadWrite.All'                     = 'Full read/write to all directory objects - users, groups, devices, apps. Can create, delete, or modify anything in Entra ID.'
    'RoleManagement.ReadWrite.Directory'          = 'Can assign or remove Entra ID directory roles, including Global Administrator - a direct path to full tenant takeover.'
    'Application.ReadWrite.All'                   = 'Can create or modify any app registration or service principal in the tenant, including granting itself additional permissions later.'
    'DeviceManagementApps.ReadWrite.All'          = 'Full control over Intune app deployment - can push arbitrary Win32/LOB app deployments to every managed device.'
    'DeviceManagementConfiguration.ReadWrite.All' = 'Full control over Intune device configuration profiles and compliance policies across the estate.'
    'DeviceManagementManagedDevices.ReadWrite.All'= 'Can read and remotely wipe, retire, or otherwise manage every Intune-enrolled device.'
    'Mail.ReadWrite'                              = 'Read and write mail in every mailbox in the tenant - not scoped to a single user.'
    'User.ReadWrite.All'                          = 'Full read/write to every user object in the tenant, including the ability to reset passwords.'
}

# Microsoft's own "Microsoft Services" tenant ID — first-party apps owned by this tenant (e.g. Office,
# Teams, SharePoint Online first-party service principals) are excluded from third-party findings.
$script:MicrosoftServicesTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
#endregion

#region Connect to Microsoft Graph
$requiredScopes = @('Application.Read.All', 'Directory.Read.All')

try {
    Write-Host "[INFO] Connecting to Microsoft Graph..." -ForegroundColor Gray
    if ($TenantId) {
        Connect-MgGraph -TenantId $TenantId -Scopes $requiredScopes -NoWelcome
    }
    else {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    }
}
catch {
    Write-Host "[FAIL] Could not connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$context = Get-MgContext
Write-Host "`n=== Enterprise App / OAuth Consent Risk Audit ===" -ForegroundColor Cyan
Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Gray
Write-Host "Account: $($context.Account)`n" -ForegroundColor Gray
#endregion

#region Resolve the Microsoft Graph service principal and build permission-name -> GUID lookups
Write-Host "[INFO] Resolving Microsoft Graph service principal and permission catalog..." -ForegroundColor Gray

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" `
    -Property Id, AppId, AppRoles, Oauth2PermissionScopes

if (-not $graphSp) {
    Write-Host "[FAIL] Could not resolve the Microsoft Graph service principal in this tenant. Aborting." -ForegroundColor Red
    return
}

# AppRoleId (GUID, as string) -> permission name, for APPLICATION permissions
$script:AppRoleLookup = @{}
# Oauth2PermissionScope Id (GUID, as string) -> permission name, for DELEGATED permissions
$script:DelegatedScopeLookup = @{}

foreach ($permName in $script:HighRiskPermissions.Keys) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
    if ($role) { $script:AppRoleLookup[$role.Id.ToString()] = $permName }

    $scope = $graphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $permName }
    if ($scope) { $script:DelegatedScopeLookup[$scope.Id.ToString()] = $permName }
}

Write-Host "[INFO] Resolved $($script:AppRoleLookup.Count) application-permission GUIDs and $($script:DelegatedScopeLookup.Count) delegated-scope GUIDs from the high-risk catalog`n" -ForegroundColor Gray
#endregion

#region Enumerate every enterprise application (service principal) in the tenant
Write-Host "[INFO] Enumerating enterprise applications (service principals)... this can take a few minutes in large tenants." -ForegroundColor Gray

$allServicePrincipals = Get-MgServicePrincipal -All `
    -Property Id, AppId, DisplayName, VerifiedPublisher, ServicePrincipalType, AppOwnerOrganizationId

$thirdPartyApps = $allServicePrincipals | Where-Object {
    $_.AppOwnerOrganizationId -ne $script:MicrosoftServicesTenantId -and
    $_.Id -ne $graphSp.Id
}

Write-Host "[INFO] Found $($allServicePrincipals.Count) total enterprise applications, $($thirdPartyApps.Count) after excluding first-party Microsoft apps`n" -ForegroundColor Gray
#endregion

#region Evaluate each service principal for high-risk permissions and publisher verification
$results = New-Object System.Collections.Generic.List[object]
$counter = 0

foreach ($sp in $thirdPartyApps) {
    $counter++
    Write-Progress -Activity "Auditing enterprise applications" -Status $sp.DisplayName `
        -PercentComplete (($counter / [math]::Max($thirdPartyApps.Count, 1)) * 100)

    $foundPermissions = New-Object System.Collections.Generic.List[string]

    # Application permissions (app role assignments) — these run 24/7 with no signed-in user present
    try {
        $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        foreach ($assignment in $appRoleAssignments) {
            if ($assignment.ResourceId -eq $graphSp.Id -and $script:AppRoleLookup.ContainsKey($assignment.AppRoleId.ToString())) {
                $foundPermissions.Add($script:AppRoleLookup[$assignment.AppRoleId.ToString()])
            }
        }
    }
    catch {
        Write-Verbose "Could not read app role assignments for $($sp.DisplayName): $($_.Exception.Message)"
    }

    # Delegated permissions (OAuth2 permission grants) — ride on top of a signed-in user's own access,
    # but a tenant-wide grant (consentType 'AllPrincipals') is still worth flagging when it touches
    # mail or directory data rather than a single user's own resources.
    try {
        $oauthGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -All -ErrorAction Stop
        foreach ($grant in $oauthGrants) {
            if ($grant.ResourceId -ne $graphSp.Id -or [string]::IsNullOrWhiteSpace($grant.Scope)) { continue }
            foreach ($scopeName in ($grant.Scope -split ' ')) {
                if ($script:HighRiskPermissions.ContainsKey($scopeName)) {
                    $foundPermissions.Add("$scopeName (delegated, $($grant.ConsentType))")
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not read OAuth2 permission grants for $($sp.DisplayName): $($_.Exception.Message)"
    }

    $uniquePermissions = $foundPermissions | Select-Object -Unique
    $isVerified = ($null -ne $sp.VerifiedPublisher) -and (-not [string]::IsNullOrWhiteSpace($sp.VerifiedPublisher.DisplayName))

    if ($uniquePermissions.Count -eq 0) {
        $severity = 'GREEN'
    }
    elseif (-not $isVerified) {
        $severity = 'RED'
    }
    else {
        $severity = 'AMBER'
    }

    $results.Add([PSCustomObject]@{
        Severity            = $severity
        AppName             = $sp.DisplayName
        AppId               = $sp.AppId
        VerifiedPublisher   = if ($isVerified) { $sp.VerifiedPublisher.DisplayName } else { 'Not verified' }
        HighRiskPermissions = if ($uniquePermissions.Count -gt 0) { ($uniquePermissions -join '; ') } else { '(none above threshold)' }
        PermissionCount     = $uniquePermissions.Count
    })
}

Write-Progress -Activity "Auditing enterprise applications" -Completed
#endregion

#region Console report — colour coded Green / Yellow / Red
Write-Host "=== Findings ===`n" -ForegroundColor Cyan

$redFindings   = $results | Where-Object { $_.Severity -eq 'RED' }   | Sort-Object AppName
$amberFindings = $results | Where-Object { $_.Severity -eq 'AMBER' } | Sort-Object AppName
$greenFindings = $results | Where-Object { $_.Severity -eq 'GREEN' } | Sort-Object AppName

$rowsToPrint = @($redFindings) + @($amberFindings)
if ($ShowAllFindings) { $rowsToPrint += @($greenFindings) }

if ($rowsToPrint.Count -eq 0) {
    Write-Host "[OK] No enterprise applications matched the high-risk permission catalog." -ForegroundColor Green
}
else {
    foreach ($row in $rowsToPrint) {
        $colour = switch ($row.Severity) {
            'RED'   { 'Red' }
            'AMBER' { 'Yellow' }
            default { 'Green' }
        }
        Write-Host ("[{0,-5}] {1,-32} Publisher: {2,-24} {3}" -f `
                $row.Severity, $row.AppName, $row.VerifiedPublisher, $row.HighRiskPermissions) -ForegroundColor $colour
    }
}

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host ("Total enterprise applications scanned : {0}" -f $thirdPartyApps.Count) -ForegroundColor Gray
Write-Host ("RED   (high-risk perms, unverified)    : {0}" -f $redFindings.Count) -ForegroundColor $(if ($redFindings.Count -gt 0) { 'Red' } else { 'Gray' })
Write-Host ("AMBER (high-risk perms, verified)      : {0}" -f $amberFindings.Count) -ForegroundColor $(if ($amberFindings.Count -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ("GREEN (no high-risk perms found)       : {0}" -f $greenFindings.Count) -ForegroundColor Gray
#endregion

#region Optional CSV export
if ($ExportCsv) {
    $reportsFolder = Split-Path -Path $CsvPath -Parent
    if ($reportsFolder -and -not (Test-Path $reportsFolder)) {
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    }
    $results | Sort-Object @{Expression = { switch ($_.Severity) { 'RED' {0} 'AMBER' {1} default {2} } } }, AppName |
        Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "`n[INFO] Full results (RED, AMBER, and GREEN) exported to: $CsvPath" -ForegroundColor Gray
}
#endregion

Write-Host "`n[INFO] Audit complete.`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------
# REMEDIATION — NOT executed by this script. Reference syntax only, run manually after confirming
# business justification with the app owner.
# ---------------------------------------------------------------------------------------------------
#
# Remove a specific APPLICATION permission (app role assignment) from a flagged service principal:
#
#   $sp         = Get-MgServicePrincipal -Filter "displayName eq 'AI ITSM Platform'"
#   $assignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All |
#                     Where-Object { $_.AppRoleId -eq '<app-role-guid-for-the-permission-to-remove>' }
#   Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
#       -AppRoleAssignmentId $assignment.Id
#
# Remove a DELEGATED permission grant entirely (or use Update-MgOauth2PermissionGrant to narrow the
# Scope string instead of deleting the whole grant):
#
#   $grant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -All
#   Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id
#
# Requires Application.ReadWrite.All (and DelegatedPermissionGrant.ReadWrite.All for the delegated
# case) — reconnect with Connect-MgGraph -Scopes "Application.ReadWrite.All" before running these.
# ---------------------------------------------------------------------------------------------------
