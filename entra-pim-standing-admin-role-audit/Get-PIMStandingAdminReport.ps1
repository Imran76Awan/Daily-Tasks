<#
.SYNOPSIS
    Audits Microsoft Entra ID privileged directory role assignments to detect standing (permanent/active)
    admin access that should be managed through Privileged Identity Management (PIM) eligible assignments
    instead.

.DESCRIPTION
    Get-PIMStandingAdminReport.ps1 connects to Microsoft Graph using the Microsoft.Graph.Identity.Governance
    module and enumerates every built-in and custom Microsoft Entra directory role definition in the tenant.
    For each role it retrieves:

      - The current ACTIVE role assignment instances (roleAssignmentScheduleInstance) — i.e. everyone who
        currently holds the role right now, whether permanently or via a time-boxed PIM activation.
      - The current ELIGIBLE role assignment instances (roleEligibilityScheduleInstance) — i.e. everyone
        who is allowed to activate the role through PIM but does not hold it right now.

    These are two entirely separate object types in Microsoft Graph and have to be cross-referenced by
    PrincipalId + RoleDefinitionId to work out who is a "standing" (permanent) admin versus who is
    correctly using PIM just-in-time activation.

    An active assignment instance is only flagged as a finding when BOTH of the following are true:

      1. Its AssignmentType property is 'Assigned' (a direct, standing assignment made outside of PIM)
         rather than 'Activated' (a temporary assignment created when a user activates an eligible
         assignment through PIM — these expire automatically and are NOT findings).
      2. There is no matching eligible schedule instance for the same principal and role — meaning the
         assignment was never intended to be time-boxed through PIM at all.

    Standing assignments on a curated list of highly privileged roles (Global Administrator, Privileged
    Role Administrator, Privileged Authentication Administrator, Security Administrator) are flagged RED.
    Standing assignments on any other built-in or custom directory role are flagged AMBER.

    This script is READ-ONLY. It never modifies, removes, or creates any role assignment. It only reports.
    Removing a standing assignment and creating an eligible one in its place must be done deliberately
    through the Entra ID > Identity Governance > Privileged Identity Management blade (or via the
    corresponding Graph write cmdlets), never automatically, because removing the wrong assignment can
    lock administrators out of the tenant.

.NOTES
    Author          : Imran Awan
    Blog post       : https://endpointweekly.com/blog/entra-pim-standing-admin-role-audit.html
    Module required : Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users, Microsoft.Graph.Groups,
                       Microsoft.Graph.Applications
    Graph scopes    : RoleManagement.Read.Directory, Directory.Read.All, User.Read.All, Group.Read.All
    Status          : NOT yet validated end-to-end against a production tenant. The cmdlet names and
                      property names below match the documented Microsoft Graph PowerShell SDK shape for
                      the PIM v3 (unifiedRoleManagement) API as of writing, but you should dry-run this in
                      a test/pilot tenant and review the output logic before relying on it for an audit
                      finding or compliance attestation. Report any discrepancies back via the blog post
                      comments so the script can be corrected.

.EXAMPLE
    .\Get-PIMStandingAdminReport.ps1

    Connects to Microsoft Graph interactively, audits every directory role in the tenant, and prints a
    colour-coded (Green/Yellow/Red) report to the console.

.EXAMPLE
    .\Get-PIMStandingAdminReport.ps1 -ExportCsv

    Runs the audit and additionally exports every flagged standing assignment to a timestamped CSV file
    under C:\Reports\.

.EXAMPLE
    .\Get-PIMStandingAdminReport.ps1 -ExportCsv -CsvPath "C:\Temp\PIM-Standing-Admins.csv"

    Runs the audit and exports findings to a specific CSV path.

.EXAMPLE
    .\Get-PIMStandingAdminReport.ps1 -TenantId "contoso.onmicrosoft.com"

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
    [string]$CsvPath = "C:\Reports\PIM-Standing-Admins_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region Configuration
# Roles considered CRITICAL. A standing (non-PIM-activated) active assignment on one of these
# is flagged RED. Everything else that is still standing gets flagged AMBER. Adjust this list to
# match the privileged roles your tenant actually cares about (e.g. add Application Administrator,
# Cloud Application Administrator, SharePoint Administrator, Intune Administrator, etc.)
$script:CriticalRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Privileged Authentication Administrator',
    'Security Administrator'
)
#endregion

#region Connect to Microsoft Graph
$requiredScopes = @(
    'RoleManagement.Read.Directory',
    'Directory.Read.All',
    'User.Read.All',
    'Group.Read.All'
)

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
Write-Host "`n=== PIM Standing Admin Role Audit ===" -ForegroundColor Cyan
Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Gray
Write-Host "Account: $($context.Account)`n" -ForegroundColor Gray
#endregion

#region Helper — resolve a principal ID to a friendly, readable name
function Resolve-PrincipalName {
    param([Parameter(Mandatory)][string]$PrincipalId)

    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return 'Unknown principal' }

    try {
        $user = Get-MgUser -UserId $PrincipalId -Property DisplayName, UserPrincipalName -ErrorAction Stop
        return $user.UserPrincipalName
    }
    catch {
        try {
            $group = Get-MgGroup -GroupId $PrincipalId -Property DisplayName -ErrorAction Stop
            return "$($group.DisplayName) (Group)"
        }
        catch {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property DisplayName -ErrorAction Stop
                return "$($sp.DisplayName) (Service Principal)"
            }
            catch {
                return "$PrincipalId (unresolved)"
            }
        }
    }
}
#endregion

#region Pull role definitions, active assignments, and eligible assignments tenant-wide
Write-Host "[INFO] Enumerating directory role definitions..." -ForegroundColor Gray
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
Write-Host "[INFO] Found $($roleDefinitions.Count) directory role definitions" -ForegroundColor Gray

Write-Host "[INFO] Retrieving ACTIVE role assignment instances (roleAssignmentScheduleInstance)..." -ForegroundColor Gray
$activeInstances = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
Write-Host "[INFO] Found $($activeInstances.Count) active assignment instances" -ForegroundColor Gray

Write-Host "[INFO] Retrieving ELIGIBLE role assignment instances (roleEligibilityScheduleInstance)..." -ForegroundColor Gray
$eligibleInstances = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
Write-Host "[INFO] Found $($eligibleInstances.Count) eligible assignment instances`n" -ForegroundColor Gray
#endregion

#region Build a lookup of principal+role combinations that DO have a matching eligible schedule
# If an active/Assigned instance has a matching eligible instance, it usually means the tenant is
# mid-migration or the eligible record simply has not expired yet — treat it as lower confidence
# and exclude it from findings so the report only surfaces assignments with NO eligible counterpart
# at all, i.e. assignments that were never meant to go through PIM.
$eligibleLookup = @{}
foreach ($e in $eligibleInstances) {
    $key = "$($e.PrincipalId)|$($e.RoleDefinitionId)"
    $eligibleLookup[$key] = $true
}
#endregion

#region Analyse every active assignment instance for standing (permanent) access
$findings = New-Object System.Collections.Generic.List[object]

foreach ($active in $activeInstances) {

    # AssignmentType 'Activated' means this active instance exists because a user activated an
    # eligible assignment through PIM — it is time-boxed and will expire on its own. Not a finding.
    if ($active.AssignmentType -ne 'Assigned') { continue }

    $roleDef = $roleDefinitions | Where-Object { $_.Id -eq $active.RoleDefinitionId }
    if (-not $roleDef) { continue }

    $key = "$($active.PrincipalId)|$($active.RoleDefinitionId)"
    if ($eligibleLookup.ContainsKey($key)) { continue }

    $principalName = Resolve-PrincipalName -PrincipalId $active.PrincipalId

    $daysHeld = if ($active.StartDateTime) {
        [math]::Round(((Get-Date) - [datetime]$active.StartDateTime).TotalDays)
    }
    else {
        $null
    }

    $severity = if ($script:CriticalRoles -contains $roleDef.DisplayName) { 'RED' } else { 'AMBER' }

    $findings.Add([PSCustomObject]@{
        Severity       = $severity
        PrincipalName  = $principalName
        PrincipalId    = $active.PrincipalId
        RoleName       = $roleDef.DisplayName
        AssignmentType = $active.AssignmentType
        StartDateTime  = $active.StartDateTime
        DaysHeld       = $daysHeld
        DirectoryScope = $active.DirectoryScopeId
    })
}
#endregion

#region Console report — colour coded Green / Yellow / Red
Write-Host "=== Findings: standing (permanent) admin assignments outside PIM ===`n" -ForegroundColor Cyan

if ($findings.Count -eq 0) {
    Write-Host "[OK] No standing active assignments found on any directory role. Every active assignment is either PIM-activated (time-boxed) or the role has no assignees." -ForegroundColor Green
}
else {
    foreach ($finding in ($findings | Sort-Object Severity, RoleName)) {
        $colour = if ($finding.Severity -eq 'RED') { 'Red' } else { 'Yellow' }
        Write-Host ("[{0,-5}] {1,-40} {2,-35} held {3,4} day(s) (since {4})" -f `
                $finding.Severity, $finding.RoleName, $finding.PrincipalName, $finding.DaysHeld, $finding.StartDateTime) -ForegroundColor $colour
    }
}

$redCount = ($findings | Where-Object { $_.Severity -eq 'RED' }).Count
$amberCount = ($findings | Where-Object { $_.Severity -eq 'AMBER' }).Count

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host ("Total active assignment instances   : {0}" -f $activeInstances.Count) -ForegroundColor Gray
Write-Host ("Total eligible assignment instances  : {0}" -f $eligibleInstances.Count) -ForegroundColor Gray
Write-Host ("Standing (permanent) findings         : {0}  (RED: {1}, AMBER: {2})" -f $findings.Count, $redCount, $amberCount) `
    -ForegroundColor $(if ($findings.Count -gt 0) { 'Yellow' } else { 'Green' })
#endregion

#region Optional CSV export
if ($ExportCsv) {
    $reportsFolder = Split-Path -Path $CsvPath -Parent
    if ($reportsFolder -and -not (Test-Path $reportsFolder)) {
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
    }
    $findings | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "`n[INFO] Findings exported to: $CsvPath" -ForegroundColor Gray
}
#endregion

Write-Host "`n[INFO] Audit complete.`n" -ForegroundColor Cyan
