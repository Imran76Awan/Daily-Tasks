<#
.SYNOPSIS
    Shows every permission granted by a named Entra ID role and flags which
    individual permissions are privileged.

.DESCRIPTION
    The PRIVILEGED label applies at two levels: a whole role can be privileged,
    and individual permissions (resource actions) can be privileged. When you view
    a role in the Entra admin center you can see which of its permissions carry the
    label — but only if you are an admin who can see it.

    This script does the same thing from the command line. Give it a role display
    name (for example "Application Administrator") and it lists each allowed
    resource action, marks the privileged ones, and prints a count.

    READ-ONLY — this script does not create, modify, or delete anything.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/entra-privileged-roles-permissions-audit-2026.html
    Requires:    Microsoft.Graph.Authentication PowerShell module
    Permissions: RoleManagement.Read.Directory
    Graph:       BETA — the isPrivileged property is not yet in the v1.0 endpoint.
    Version:     1.0
    Date:        2026-07-21

.EXAMPLE
    .\Get-EntraRolePermissionDetail.ps1 -RoleName "Application Administrator"
    Lists the role's permissions and marks the privileged ones.

.EXAMPLE
    .\Get-EntraRolePermissionDetail.ps1 -RoleName "Helpdesk Administrator" -Interactive
    Same, using your signed-in admin account instead of certificate auth.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RoleName,
    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'

# ── Auth settings (app-only certificate) ──────────────────────────────────────
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

$base = 'https://graph.microsoft.com/beta/roleManagement/directory'

# ── 1. Find the role definition by display name ─────────────────────────────────
$escaped = $RoleName.Replace("'", "''")
$roleResp = Invoke-MgGraphRequest -Method GET `
    -Uri "$base/roleDefinitions?`$filter=displayName eq '$escaped'&`$select=id,displayName,description,isPrivileged"

if (-not $roleResp.value -or $roleResp.value.Count -eq 0) {
    Write-Host "ERROR: Role '$RoleName' not found. Check the exact display name." -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 1
}
$role = $roleResp.value[0]

Write-Host "`nRole: $($role.displayName)" -ForegroundColor White
Write-Host "  Role is privileged: $($role.isPrivileged)" -ForegroundColor $(if ($role.isPrivileged) { 'Red' } else { 'Green' })
Write-Host "  $($role.description)`n" -ForegroundColor Gray

# ── 2. Pull the full role definition (with rolePermissions) ─────────────────────
$full = Invoke-MgGraphRequest -Method GET -Uri "$base/roleDefinitions/$($role.id)"
$allowedActions = @()
foreach ($rp in $full.rolePermissions) { $allowedActions += $rp.allowedResourceActions }
$allowedActions = $allowedActions | Sort-Object -Unique

# ── 3. Build a lookup of which microsoft.directory actions are privileged ───────
$privSet = @{}
$privActions = @()
$uri = "$base/resourceNamespaces/microsoft.directory/resourceActions?`$filter=isPrivileged eq true&`$select=name"
do {
    $resp = Invoke-MgGraphRequest -Uri $uri -Method GET
    $privActions += $resp.value
    $uri = $resp.'@odata.nextLink'
} while ($uri)
foreach ($p in $privActions) { $privSet[$p.name] = $true }

# ── 4. Report ───────────────────────────────────────────────────────────────────
$report = foreach ($action in $allowedActions) {
    $isPriv = $privSet.ContainsKey($action)
    [pscustomobject]@{
        Privileged = if ($isPriv) { 'YES' } else { '' }
        Permission = $action
    }
}

$report | Format-Table Privileged, Permission -AutoSize

$privCount = @($report | Where-Object { $_.Privileged -eq 'YES' }).Count
Write-Host ("`n{0} of {1} permission(s) in '{2}' are privileged.`n" -f $privCount, $allowedActions.Count, $role.displayName) `
    -ForegroundColor $(if ($privCount -gt 0) { 'Yellow' } else { 'Green' })

Disconnect-MgGraph | Out-Null
