<#
.SYNOPSIS
    Audits every privileged role, privileged permission, and privileged role
    assignment in your Microsoft Entra ID tenant using the isPrivileged property.

.DESCRIPTION
    Microsoft now tags roles, permissions, and role assignments with an
    "isPrivileged" flag (the PRIVILEGED label, currently in preview). A privileged
    permission is one that can delegate management of directory resources, modify
    credentials, change authentication or authorization policy, or access
    restricted data — i.e. anything that can lead to elevation of privilege.

    This script queries the Microsoft Graph BETA endpoint and produces three reports:
      1. Privileged role definitions   (isPrivileged eq true)
      2. Privileged permissions        (resourceActions where isPrivileged eq true)
      3. Privileged role assignments    (who holds a privileged role, resolved to a name)

    It prints a summary to the console and optionally exports each report to CSV.

    READ-ONLY — this script does not create, modify, or delete anything.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/entra-privileged-roles-permissions-audit-2026.html
    Requires:    Microsoft.Graph.Authentication PowerShell module
    Permissions: RoleManagement.Read.Directory  (least privilege for this audit)
                 Directory.Read.All also works if you already have it.
    Graph:       BETA — the isPrivileged property is not yet in the v1.0 endpoint.
    Version:     1.0
    Date:        2026-07-21

.EXAMPLE
    .\Get-EntraPrivilegedRoleAudit.ps1
    Connects with app-only certificate auth and prints all three summaries.

.EXAMPLE
    .\Get-EntraPrivilegedRoleAudit.ps1 -ExportCsv -OutputFolder C:\Reports
    Same audit, plus writes PrivilegedRoles.csv, PrivilegedPermissions.csv and
    PrivilegedAssignments.csv to C:\Reports.

.EXAMPLE
    .\Get-EntraPrivilegedRoleAudit.ps1 -Interactive
    Uses your signed-in admin account (delegated) instead of certificate auth.
    Handy for a quick one-off check without an app registration.
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'reports'),
    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'

# ── Auth settings (app-only certificate) ──────────────────────────────────────
# Fill these in for unattended / scheduled runs. Leave as-is and use -Interactive
# for a quick manual audit signed in as an admin.
$tenantId   = 'YOUR-TENANT-ID'        # e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$clientId   = 'YOUR-APP-CLIENT-ID'    # App registration (client) ID from Entra
$thumbprint = 'YOUR-CERT-THUMBPRINT'  # Certificate thumbprint on the app registration

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host "`nConnecting to Microsoft Graph (beta)..." -ForegroundColor Cyan
if ($Interactive) {
    Connect-MgGraph -Scopes 'RoleManagement.Read.Directory' -NoWelcome
} else {
    Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -NoWelcome
}

$ctx = Get-MgContext
Write-Host "Connected to tenant: $($ctx.TenantId)" -ForegroundColor Green

# ── Helper: page through a Graph collection ────────────────────────────────────
function Get-GraphAll {
    param([string]$Uri)
    $items = @()
    do {
        $resp  = Invoke-MgGraphRequest -Uri $Uri -Method GET
        $items += $resp.value
        $Uri    = $resp.'@odata.nextLink'
    } while ($Uri)
    return $items
}

$base = 'https://graph.microsoft.com/beta/roleManagement/directory'

# ── 1. Privileged role definitions ─────────────────────────────────────────────
Write-Host "`n[1/3] Fetching privileged role definitions..." -ForegroundColor Cyan
$roles = Get-GraphAll "$base/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,displayName,description,isBuiltIn,isEnabled"

$roleReport = $roles | Sort-Object displayName | ForEach-Object {
    [pscustomobject]@{
        DisplayName = $_.displayName
        RoleId      = $_.id
        BuiltIn     = $_.isBuiltIn
        Enabled     = $_.isEnabled
        Description = $_.description
    }
}

Write-Host ("      {0} privileged role(s) found." -f $roleReport.Count) -ForegroundColor Yellow
$roleReport | Format-Table DisplayName, BuiltIn, Enabled -AutoSize

# ── 2. Privileged permissions (microsoft.directory namespace) ───────────────────
Write-Host "`n[2/3] Fetching privileged permissions (microsoft.directory)..." -ForegroundColor Cyan
$perms = Get-GraphAll "$base/resourceNamespaces/microsoft.directory/resourceActions?`$filter=isPrivileged eq true&`$select=id,name,description,actionVerb"

$permReport = $perms | Sort-Object name | ForEach-Object {
    [pscustomobject]@{
        Permission  = $_.name
        Verb        = $_.actionVerb
        Description = $_.description
    }
}

Write-Host ("      {0} privileged permission(s) found." -f $permReport.Count) -ForegroundColor Yellow
$permReport | Select-Object -First 15 | Format-Table Permission, Verb -AutoSize
if ($permReport.Count -gt 15) { Write-Host ("      ...and {0} more (see CSV/full output)." -f ($permReport.Count - 15)) -ForegroundColor DarkGray }

# ── 3. Privileged role assignments (resolve principals to names) ────────────────
Write-Host "`n[3/3] Fetching privileged role assignments..." -ForegroundColor Cyan
$assignments = Get-GraphAll "$base/roleAssignments?`$expand=roleDefinition&`$filter=roleDefinition/isPrivileged eq true"

$assignmentReport = foreach ($a in $assignments) {
    # Resolve the principal (user / group / service principal) to a friendly name.
    $principalName = '(unresolved)'
    $principalType = 'unknown'
    try {
        $obj = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/directoryObjects/$($a.principalId)" -Method GET
        $principalName = $obj.displayName
        if ($obj.userPrincipalName) { $principalName = $obj.userPrincipalName }
        $principalType = ($obj.'@odata.type' -replace '#microsoft.graph.', '')
    } catch {
        Write-Verbose "Could not resolve principal $($a.principalId): $($_.Exception.Message)"
    }

    [pscustomobject]@{
        Role          = $a.roleDefinition.displayName
        Principal     = $principalName
        PrincipalType = $principalType
        PrincipalId   = $a.principalId
        Scope         = $a.directoryScopeId
    }
}

Write-Host ("      {0} privileged role assignment(s) found." -f @($assignmentReport).Count) -ForegroundColor Yellow
$assignmentReport | Sort-Object Role, Principal | Format-Table Role, Principal, PrincipalType, Scope -AutoSize

# ── Global Administrator spotlight (the one to keep < 5) ────────────────────────
$gaCount = @($assignmentReport | Where-Object { $_.Role -eq 'Global Administrator' }).Count
Write-Host "`nGlobal Administrator assignments: $gaCount" -ForegroundColor $(if ($gaCount -gt 5) { 'Red' } else { 'Green' })
if ($gaCount -gt 5) {
    Write-Host "  WARNING: Microsoft recommends fewer than 5 Global Administrators. You have $gaCount." -ForegroundColor Red
}
$totalPriv = @($assignmentReport).Count
Write-Host "Total privileged assignments: $totalPriv" -ForegroundColor $(if ($totalPriv -gt 10) { 'Red' } else { 'Green' })
if ($totalPriv -gt 10) {
    Write-Host "  WARNING: Microsoft recommends fewer than 10 privileged assignments. You have $totalPriv." -ForegroundColor Red
}

# ── Optional CSV export ─────────────────────────────────────────────────────────
if ($ExportCsv) {
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $roleReport       | Export-Csv (Join-Path $OutputFolder "PrivilegedRoles-$stamp.csv")       -NoTypeInformation -Encoding UTF8
    $permReport       | Export-Csv (Join-Path $OutputFolder "PrivilegedPermissions-$stamp.csv") -NoTypeInformation -Encoding UTF8
    $assignmentReport | Export-Csv (Join-Path $OutputFolder "PrivilegedAssignments-$stamp.csv") -NoTypeInformation -Encoding UTF8
    Write-Host "`nCSV reports written to: $OutputFolder" -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null
Write-Host "`nAudit complete.`n" -ForegroundColor Cyan
