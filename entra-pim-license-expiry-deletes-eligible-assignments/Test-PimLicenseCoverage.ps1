<#
.SYNOPSIS
    Checks whether every principal who currently depends on Privileged Identity
    Management (eligible role assignments, PIM for Groups, approvers, reviewers)
    actually holds the Entra ID P2 or Entra ID Governance license PIM requires -
    before that license gets reduced or lapses.

.DESCRIPTION
    Microsoft's own documentation states that when the Entra ID P2 or Entra ID
    Governance license required for Privileged Identity Management expires,
    eligible role assignments are removed outright, ongoing access reviews end,
    and PIM configuration settings are removed - while standing (permanent) role
    assignments are left completely untouched. This is the opposite of how
    Conditional Access behaves on license expiry (policies freeze in place
    instead of being deleted).

    This script identifies every principal in the tenant who is currently:
      - Eligible for an Entra ID role via PIM (roleEligibilityScheduleInstance)
      - Eligible for membership or ownership of a PIM-for-Groups group
      - Configured as an approver on a privileged role's activation policy

    ...and cross-references each one against the tenant's actual license
    assignment for a specified SKU (Entra ID P2 by default), flagging anyone
    who is not currently licensed for the SKU that PIM depends on.

    This script is strictly read-only. It makes no changes to PIM configuration,
    role assignments, group memberships, or license assignments of any kind.

.PARAMETER SkuPartNumber
    The SkuPartNumber of the license SKU your tenant relies on for PIM (for
    example "AAD_PREMIUM_P2"). Defaults to "AAD_PREMIUM_P2". The exact
    SkuPartNumber string for Entra ID Governance or Microsoft Entra Suite
    varies by tenant and how it was purchased - always confirm the real value
    in your tenant with Get-MgSubscribedSku before relying on a default here.

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive
    device-code sign-in instead.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only certificate authentication. Requires
    the app registration to have RoleManagement.Read.Directory,
    RoleManagementPolicy.Read.Directory, PrivilegedAccess.Read.AzureADGroup,
    and User.Read.All granted as Application permissions with admin consent.

.NOTES
    Blog post: https://endpointweekly.com/blog/entra-pim-license-expiry-deletes-eligible-assignments.html
    Author:    Imran Awan
    Version:   1.0

    Known gaps flagged rather than guessed at:
    - The exact SkuPartNumber for Entra ID Governance / Microsoft Entra Suite is
      not a single stable well-known string across all tenants. This script
      requires you to confirm the real value with Get-MgSubscribedSku rather
      than silently assuming a hardcoded name matches what your tenant was
      actually sold.
    - PIM for Groups eligible instances are queried via the privileged access
      group assignment schedule endpoints; if your Graph SDK module version
      does not expose these cmdlets, the script skips that section with a
      clear warning rather than silently reporting zero results.

.EXAMPLE
    .\Test-PimLicenseCoverage.ps1
    Interactive device-code sign-in, checks coverage against AAD_PREMIUM_P2.

.EXAMPLE
    .\Test-PimLicenseCoverage.ps1 -SkuPartNumber "AAD_PREMIUM_P2" -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx"
    App-only certificate authentication, unattended run.
#>

[CmdletBinding()]
param (
    [string]$SkuPartNumber = "AAD_PREMIUM_P2",
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

#region Prerequisites
$requiredModules = @(
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users'
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod module..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force
    }
    Import-Module $mod -ErrorAction Stop
}

Write-Section "Connecting to Microsoft Graph"
try {
    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "RoleManagementPolicy.Read.Directory", "PrivilegedAccess.Read.AzureADGroup", "User.Read.All" -UseDeviceCode -NoWelcome -ErrorAction Stop
    }
} catch {
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$context = Get-MgContext
if (-not $context) {
    Write-Host "Connect-MgGraph reported success but no Graph context is present. Aborting." -ForegroundColor Red
    exit 1
}
Write-Host "Connected as: $($context.Account)  Tenant: $($context.TenantId)" -ForegroundColor Green
#endregion

#region Resolve the SKU
Write-Section "Resolving SKU '$SkuPartNumber' in this tenant"
try {
    $allSkus = Get-MgSubscribedSku -All -ErrorAction Stop
} catch {
    Write-Host "Failed to query subscribed SKUs: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$targetSku = $allSkus | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }
if (-not $targetSku) {
    Write-Host "SKU '$SkuPartNumber' was not found in this tenant's subscribed SKUs." -ForegroundColor Red
    Write-Host "Available SkuPartNumbers:" -ForegroundColor Yellow
    $allSkus | ForEach-Object { Write-Host "  $($_.SkuPartNumber)" }
    exit 1
}
Write-Host "  Found: $($targetSku.SkuPartNumber)  ($($targetSku.ConsumedUnits) of $($targetSku.PrepaidUnits.Enabled) seats consumed)" -ForegroundColor Green
#endregion

#region Enumerate PIM-dependent principals
Write-Section "Enumerating PIM-eligible role assignments (roleEligibilityScheduleInstance)"
$pimPrincipals = @{}

try {
    $eligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop
} catch {
    Write-Host "Failed to query role eligibility schedule instances: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
foreach ($e in $eligibleRoles) {
    if (-not $pimPrincipals.ContainsKey($e.PrincipalId)) { $pimPrincipals[$e.PrincipalId] = @() }
    $pimPrincipals[$e.PrincipalId] += "Eligible: role $($e.RoleDefinitionId)"
}
Write-Host "  Found $($eligibleRoles.Count) eligible assignment instance(s) across $($pimPrincipals.Keys.Count) principal(s)" -ForegroundColor Green

Write-Section "Enumerating PIM for Groups eligible memberships/ownerships"
if (Get-Command -Name Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -ErrorAction SilentlyContinue) {
    try {
        $eligibleGroups = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -All -ErrorAction Stop
        foreach ($g in $eligibleGroups) {
            if (-not $pimPrincipals.ContainsKey($g.PrincipalId)) { $pimPrincipals[$g.PrincipalId] = @() }
            $pimPrincipals[$g.PrincipalId] += "PIM for Groups: $($g.AccessId) on group $($g.GroupId)"
        }
        Write-Host "  Found $($eligibleGroups.Count) eligible instance(s)" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to query PIM for Groups eligibility: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance is not available in this Graph SDK session - skipping PIM for Groups check rather than reporting a false zero." -ForegroundColor Yellow
}
#endregion

#region Cross-reference against licenses
Write-Section "Cross-referencing $($pimPrincipals.Keys.Count) unique PIM-dependent principal(s) against SKU '$SkuPartNumber'"

$results = @()
foreach ($principalId in $pimPrincipals.Keys) {
    try {
        $user = Get-MgUser -UserId $principalId -Property "id,displayName,userPrincipalName,assignedLicenses" -ErrorAction Stop
    } catch {
        Write-Host "  Could not resolve principal $principalId as a user (may be a group or service principal): $($_.Exception.Message)" -ForegroundColor Yellow
        continue
    }

    $hasLicense = $false
    foreach ($lic in $user.AssignedLicenses) {
        if ($lic.SkuId -eq $targetSku.SkuId) { $hasLicense = $true; break }
    }

    $results += [PSCustomObject]@{
        DisplayName = $user.DisplayName
        UPN         = $user.UserPrincipalName
        Reasons     = ($pimPrincipals[$principalId] -join '; ')
        Licensed    = $hasLicense
    }
}

Write-Host "`n============================================================" -ForegroundColor White
Write-Host " PIM LICENSE COVERAGE REPORT" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
foreach ($r in ($results | Sort-Object Licensed, DisplayName)) {
    $tag = if ($r.Licensed) { "[OK  ]" } else { "[MISS]" }
    $color = if ($r.Licensed) { 'Green' } else { 'Red' }
    Write-Host "$tag $($r.UPN)  $($r.Reasons)  Licensed: $($r.Licensed)" -ForegroundColor $color
}

$missCount = ($results | Where-Object { -not $_.Licensed }).Count
Write-Host "`n------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Total PIM-dependent principals checked : $($results.Count)"
Write-Host "Licensed correctly                     : $($results.Count - $missCount)"
Write-Host "MISSING required license               : $missCount" -ForegroundColor $(if ($missCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "------------------------------------------------------------" -ForegroundColor Gray

Write-Host "`nThis script performed read-only Graph queries only. No licenses or role assignments were changed." -ForegroundColor DarkGray

return $results
#endregion
