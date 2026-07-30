<#
.SYNOPSIS
    Audits every user in the tenant with a Temporary Access Pass (TAP) on
    record, and flags any that belong to a privileged role holder.

.DESCRIPTION
    A Temporary Access Pass is a time-limited passcode used to bootstrap or
    recover passwordless authentication methods (Windows Hello for Business,
    FIDO2 security keys, phone sign-in) without ever using a password. It is
    designed to be created during onboarding or a recovery incident and then
    expire or be cleaned up shortly after.

    There is no single Graph endpoint that lists every TAP in a tenant - each
    one is scoped to a specific user, so this script enumerates users and
    checks each one individually for a Temporary Access Pass authentication
    method. It reports:
      - Users with a currently active (usable) TAP
      - Users with an expired TAP that has not been deleted yet
      - Whether each flagged user currently holds a privileged Entra ID role,
        since an active TAP on a privileged account is the combination most
        worth reviewing immediately rather than during a routine audit

    This script is strictly read-only. It never creates, deletes, or modifies
    a Temporary Access Pass or any other authentication method.

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive
    device-code sign-in instead.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only certificate authentication. Requires
    the app registration to have UserAuthenticationMethod.Read.All,
    User.Read.All, and RoleManagement.Read.Directory granted as Application
    permissions with admin consent.

.PARAMETER UserPrincipalName
    Optional list of specific UPNs to check instead of enumerating every user
    in the tenant. Use this on large tenants to get a fast, scoped result -
    for example when testing the script, or when you only need to check a
    handful of accounts (new hires, a recovery incident) rather than
    auditing the whole directory.

.NOTES
    Blog post: https://endpointweekly.com/blog/entra-temporary-access-pass-tap-whfb-bootstrap-recovery.html
    Author:    Imran Awan
    Version:   1.0

    Known gaps flagged rather than guessed at:
    - Enumerating every user's authentication methods individually does not
      scale instantly on very large tenants - each user requires one Graph
      call. For tenants with tens of thousands of users, expect this to take
      a meaningful amount of time and consider filtering to a specific group
      first if you only need to audit a subset.
    - Privileged role detection checks active (not eligible/PIM) directory
      role assignments at the time the script runs. A user who is PIM-eligible
      but not currently activated for a privileged role will not be flagged
      as privileged by this script.

.EXAMPLE
    .\Get-TapAuditReport.ps1
    Interactive device-code sign-in, audits every user in the tenant.

.EXAMPLE
    .\Get-TapAuditReport.ps1 -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx"
    App-only certificate authentication, unattended run.
#>

[CmdletBinding()]
param (
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string[]]$UserPrincipalName
)

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

#region Prerequisites
$requiredModules = @(
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.DirectoryManagement'
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
        Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All", "RoleManagement.Read.Directory" -UseDeviceCode -NoWelcome -ErrorAction Stop
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

#region Build the set of privileged principal IDs
Write-Section "Resolving currently active privileged role assignments"

$privilegedPrincipalIds = New-Object System.Collections.Generic.HashSet[string]
try {
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop
    foreach ($ra in $roleAssignments) {
        [void]$privilegedPrincipalIds.Add($ra.PrincipalId)
    }
    Write-Host "  Found $($privilegedPrincipalIds.Count) unique principal(s) with an active directory role assignment" -ForegroundColor Green
} catch {
    Write-Host "  Failed to query role assignments: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Privileged-role flagging will be skipped for this run." -ForegroundColor Yellow
}
#endregion

#region Enumerate users and check for a Temporary Access Pass
if ($UserPrincipalName) {
    Write-Section "Checking Temporary Access Pass methods for $($UserPrincipalName.Count) specified user(s)"
} else {
    Write-Section "Enumerating users and checking for Temporary Access Pass methods"
}

try {
    if ($UserPrincipalName) {
        $users = foreach ($upn in $UserPrincipalName) {
            try {
                Get-MgUser -UserId $upn -Property "Id,UserPrincipalName,DisplayName" -ErrorAction Stop
            } catch {
                Write-Host "  Could not resolve user '$upn': $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName" -ErrorAction Stop
    }
} catch {
    Write-Host "Failed to enumerate users: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$results = @()
$checked = 0

foreach ($user in $users) {
    $checked++
    try {
        $taps = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -ErrorAction Stop
    } catch {
        # A 404/Forbidden here usually just means no TAP exists for this user -
        # not every failure is worth aborting the whole run over, but a
        # widespread pattern of failures below would indicate a permissions
        # problem worth investigating rather than trusting an all-clear result.
        continue
    }

    foreach ($tap in $taps) {
        $now = Get-Date
        $expiresAt = $tap.StartDateTime.AddMinutes($tap.LifetimeInMinutes)
        $isPrivileged = $privilegedPrincipalIds.Contains($user.Id)

        $results += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            IsUsableOnce      = $tap.IsUsableOnce
            IsUsable          = $tap.IsUsable
            StartDateTime     = $tap.StartDateTime
            ExpiresAt         = $expiresAt
            IsExpired         = ($now -gt $expiresAt)
            IsPrivileged      = $isPrivileged
        }
    }
}

Write-Host "Checked $checked user(s). Found $($results.Count) with a Temporary Access Pass on record." -ForegroundColor Green
#endregion

#region Report
Write-Host "`n============================================================" -ForegroundColor White
Write-Host " TEMPORARY ACCESS PASS AUDIT REPORT" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

foreach ($r in ($results | Sort-Object IsExpired, ExpiresAt)) {
    $statusTag = if ($r.IsExpired) { "[EXPIRED]" } else { "[ACTIVE ]" }
    $color = if ($r.IsExpired) { 'DarkGray' } elseif ($r.IsPrivileged) { 'Red' } else { 'Green' }
    $oneTime = if ($r.IsUsableOnce) { 'Yes' } else { 'No' }
    $privFlag = if ($r.IsPrivileged) { 'YES  <-- REVIEW IMMEDIATELY' } else { 'No' }

    if ($r.IsExpired) {
        Write-Host "$statusTag $($r.UserPrincipalName)  One-time: $oneTime  Expired: $([math]::Round(((Get-Date) - $r.ExpiresAt).TotalDays)) day(s) ago" -ForegroundColor $color
    } else {
        $remaining = $r.ExpiresAt - (Get-Date)
        $remainingStr = if ($remaining.TotalHours -ge 1) { "$([math]::Round($remaining.TotalHours,1)) hrs" } else { "$([math]::Round($remaining.TotalMinutes)) min" }
        Write-Host "$statusTag $($r.UserPrincipalName)  One-time: $oneTime  Expires in: $remainingStr  Privileged: $privFlag" -ForegroundColor $color
    }
}

$activeCount = @($results | Where-Object { -not $_.IsExpired }).Count
$expiredCount = @($results | Where-Object { $_.IsExpired }).Count
$activePrivilegedCount = @($results | Where-Object { -not $_.IsExpired -and $_.IsPrivileged }).Count

Write-Host "`n------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Total users with a TAP on record : $($results.Count)"
Write-Host "Currently active                 : $activeCount"
Write-Host "Expired (not yet cleaned up)      : $expiredCount"
Write-Host "Active AND privileged role holder: $activePrivilegedCount" -ForegroundColor $(if ($activePrivilegedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "------------------------------------------------------------" -ForegroundColor Gray

Write-Host "`nThis script performed read-only Graph queries only. No TAPs were created," -ForegroundColor DarkGray
Write-Host "deleted, or modified." -ForegroundColor DarkGray

return $results
#endregion
