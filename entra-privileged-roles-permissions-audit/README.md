# Entra Privileged Roles & Permissions Audit

Read-only PowerShell for auditing the new **PRIVILEGED** label in Microsoft Entra ID
(the `isPrivileged` property, currently in preview).

Companion scripts for the EndpointWeekly post:
**[Find Every Privileged Role, Permission & Assignment in Entra ID](https://endpointweekly.com/blog/entra-privileged-roles-permissions-audit-2026.html)**

## Scripts

| Script | What it does |
|--------|--------------|
| `Get-EntraPrivilegedRoleAudit.ps1` | Lists all privileged **roles**, privileged **permissions**, and privileged **role assignments** (resolved to user/group/SP names). Flags if you exceed Microsoft's recommended limits (< 5 Global Admins, < 10 privileged assignments). Optional CSV export. |
| `Get-EntraRolePermissionDetail.ps1` | For a single role, lists every allowed permission and marks which ones are privileged. |

## Requirements

- **Module:** `Microsoft.Graph.Authentication`
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```
- **Permission:** `RoleManagement.Read.Directory` (least privilege) or `Directory.Read.All`
- **Graph endpoint:** BETA — `isPrivileged` is not yet in `v1.0`.

## Authentication

Both scripts support two modes:

- **App-only (certificate)** — default. Fill in `$tenantId`, `$clientId`, `$thumbprint` at the
  top of each script. Best for scheduled/unattended runs.
- **Interactive** — add `-Interactive` to sign in as an admin. Best for a quick one-off check.

## Examples

```powershell
# Full tenant audit, console only
.\Get-EntraPrivilegedRoleAudit.ps1 -Interactive

# Full audit + CSV export
.\Get-EntraPrivilegedRoleAudit.ps1 -ExportCsv -OutputFolder C:\Reports

# Inspect a single role's permissions
.\Get-EntraRolePermissionDetail.ps1 -RoleName "Application Administrator" -Interactive
```

## Safety

Both scripts are **read-only**. They call only `GET` against Microsoft Graph and never
create, modify, or delete roles, permissions, or assignments.
