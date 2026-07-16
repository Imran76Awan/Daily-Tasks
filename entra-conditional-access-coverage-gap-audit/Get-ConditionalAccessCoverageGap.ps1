<#
.SYNOPSIS
    Finds every user and workload identity (service principal) in your Entra ID
    tenant that has ZERO applicable, enforced Conditional Access policy.

.DESCRIPTION
    Conditional Access policies target groups and applications — not "all users"
    by default — so coverage gaps open silently over time: new starters who
    haven't been added to a targeting group yet, guest/B2B accounts caught by an
    old exclusion group that nobody has reviewed, break-glass accounts excluded
    years ago and forgotten, new app registrations nobody assigned to a policy,
    and — the one almost everyone misses — workload identities (service
    principals / managed identities), which require a SEPARATE Conditional
    Access policy type scoped to client applications, not user sign-ins.

    Entra ID has no built-in report that answers "which users have no applicable
    policy at all" — the What If tool only checks one user at a time and only
    evaluates user/sign-in based policies, not workload identity policies. This
    script computes the answer for the whole tenant in one pass.

    LOGIC:
      1. Pull every Conditional Access policy and split by State:
           - enabled                          -> ENFORCED
           - enabledForReportingButNotEnforced -> REPORT-ONLY (does NOT block/require anything)
           - disabled                          -> ignored entirely
      2. Expand every group referenced in IncludeGroups/ExcludeGroups into a
         flat set of member IDs (cached so each group is only resolved once).
      3. For every enabled user, work out whether ANY enforced policy's
         effective include set contains them and does NOT also exclude them.
           - Zero enforced policies apply           -> RED   (no coverage)
           - Only report-only policies apply         -> AMBER (fake sense of coverage)
           - At least one enforced policy applies    -> GREEN (covered)
      4. Repeat the same include/exclude resolution for service principals
         against policies that use conditions.clientApplications (workload
         identity policies) rather than conditions.users.

    READ-ONLY — this script does not create, modify, or delete anything. It only
    reads policies, users, group membership, and service principals and reports
    on what it finds.

    LIMITATIONS (read before you rely on this):
      - Role-based targeting (Conditions.Users.IncludeRoles / ExcludeRoles) is
        NOT expanded in this version — a policy that targets a directory role
        (e.g. "Global Administrators") is flagged as SKIPPED-ROLE-SCOPE rather
        than resolved to members. Extend Get-RoleMemberIds if you use role-based
        CA targeting and need it included in the coverage calculation.
      - "GuestsOrExternalUsers" and other special IncludeUsers/IncludeGuestsOrExternalUsers
        values are treated as matching all guest/external UserType accounts only
        — cross-check manually if you use the granular external tenant
        categories (b2bCollaborationGuest, b2bCollaborationMember, etc.).
      - Named locations, sign-in risk, device platform, and client app
        conditions are NOT evaluated — this script only answers "does an
        enforced policy's USER/APP TARGETING include this identity", which is
        the coverage-gap question. It does not replicate full CA policy
        evaluation (that is what the What If tool is for, one user at a time).
      - This script has not been validated against a live production tenant.
        Treat the output as a starting point for manual verification, not as
        an authoritative compliance report. Review and test before you rely on
        it operationally.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/entra-conditional-access-coverage-gap-audit.html
    Requires:    Microsoft.Graph PowerShell SDK (Microsoft.Graph.Identity.SignIns,
                 Microsoft.Graph.Users, Microsoft.Graph.Groups,
                 Microsoft.Graph.Applications)
    Permissions: Policy.Read.All, User.Read.All, Group.Read.All,
                 Application.Read.All, Directory.Read.All (delegated or app-only)
    Version:     1.0
    Date:        2026-07-16
    Status:      NOT yet tested against a live tenant. Review the logic, run it
                 read-only against a test/pilot tenant first, and validate a
                 sample of the RED/AMBER results manually with the What If tool
                 before trusting the output at scale.

.EXAMPLE
    .\Get-ConditionalAccessCoverageGap.ps1
    Connects interactively, scans the tenant, and prints a colour-coded summary
    to the console.

.EXAMPLE
    .\Get-ConditionalAccessCoverageGap.ps1 -ExportCsv "C:\Reports\ca-coverage-gap.csv"
    Same scan, plus writes the full per-identity result set to CSV.

.EXAMPLE
    .\Get-ConditionalAccessCoverageGap.ps1 -SkipServicePrincipals
    Scans users only — skips the workload identity (service principal) pass,
    useful for a faster run in a tenant where Workload Identities Premium is
    not licensed and no workload identity CA policies exist.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServicePrincipals,

    # Optional app-only auth (unattended / scheduled runs). Leave all three
    # blank to fall back to interactive Connect-MgGraph.
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

$requiredScopes = @(
    'Policy.Read.All',
    'User.Read.All',
    'Group.Read.All',
    'Application.Read.All',
    'Directory.Read.All'
)

if ($TenantId -and $ClientId -and $CertificateThumbprint) {
    Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome
}
else {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
}

$ctx = Get-MgContext
Write-Host "Connected as: $($ctx.Account)  Tenant: $($ctx.TenantId)" -ForegroundColor Green

# ── Helper: expand a set of group IDs into a flat HashSet of member object IDs ─
$script:GroupMemberCache = @{}

function Get-ExpandedGroupMemberIds {
    param([string[]]$GroupIds)

    $result = [System.Collections.Generic.HashSet[string]]::new()
    if (-not $GroupIds) { return $result }

    foreach ($groupId in $GroupIds) {
        if ([string]::IsNullOrWhiteSpace($groupId)) { continue }

        if (-not $script:GroupMemberCache.ContainsKey($groupId)) {
            Write-Verbose "Resolving group membership for $groupId"
            try {
                $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
                $script:GroupMemberCache[$groupId] = @($members | ForEach-Object { $_.Id })
            }
            catch {
                Write-Warning "Could not expand group $groupId : $($_.Exception.Message)"
                $script:GroupMemberCache[$groupId] = @()
            }
        }

        foreach ($id in $script:GroupMemberCache[$groupId]) {
            [void]$result.Add($id)
        }
    }
    return $result
}

# ── Helper: does this policy's USER targeting cover a given user? ─────────────
function Test-UserCoveredByPolicy {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [string]$UserType   # 'Member' or 'Guest'
    )

    $userCond = $Policy.Conditions.Users
    if (-not $userCond) { return $false }

    $includeUsers  = @($userCond.IncludeUsers)
    $excludeUsers  = @($userCond.ExcludeUsers)
    $includeGroups = @($userCond.IncludeGroups)
    $excludeGroups = @($userCond.ExcludeGroups)

    # --- Resolve INCLUDE ---
    $includesAll        = $includeUsers -contains 'All'
    $includesGuestsOnly  = $includeUsers -contains 'GuestsOrExternalUsers'
    $includeSet          = Get-ExpandedGroupMemberIds -GroupIds $includeGroups
    foreach ($u in $includeUsers) {
        if ($u -notin @('All', 'GuestsOrExternalUsers', 'None')) { [void]$includeSet.Add($u) }
    }

    $isIncluded = $false
    if ($includesAll) { $isIncluded = $true }
    elseif ($includesGuestsOnly -and $UserType -eq 'Guest') { $isIncluded = $true }
    elseif ($includeSet.Contains($UserId)) { $isIncluded = $true }

    if (-not $isIncluded) { return $false }

    # --- Resolve EXCLUDE (exclude always wins) ---
    $excludeSet = Get-ExpandedGroupMemberIds -GroupIds $excludeGroups
    foreach ($u in $excludeUsers) {
        if ($u -notin @('All', 'GuestsOrExternalUsers', 'None')) { [void]$excludeSet.Add($u) }
    }
    $excludesGuestsOnly = $excludeUsers -contains 'GuestsOrExternalUsers'

    if ($excludeSet.Contains($UserId)) { return $false }
    if ($excludesGuestsOnly -and $UserType -eq 'Guest') { return $false }

    return $true
}

# ── Helper: does this policy's CLIENT APPLICATION targeting cover a given SPN? ─
function Test-ServicePrincipalCoveredByPolicy {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$ServicePrincipalId
    )

    $clientAppCond = $Policy.Conditions.ClientApplications
    if (-not $clientAppCond) { return $false }   # this policy is not a workload identity policy

    $includeSpns = @($clientAppCond.IncludeServicePrincipals)
    $excludeSpns = @($clientAppCond.ExcludeServicePrincipals)

    $isIncluded = ($includeSpns -contains 'All') -or ($includeSpns -contains $ServicePrincipalId)
    if (-not $isIncluded) { return $false }

    if ($excludeSpns -contains $ServicePrincipalId) { return $false }

    return $true
}

# ── Pull policies ─────────────────────────────────────────────────────────────
Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan
$allPolicies = Get-MgIdentityConditionalAccessPolicy -All

$enforcedPolicies   = @($allPolicies | Where-Object { $_.State -eq 'enabled' })
$reportOnlyPolicies = @($allPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
$disabledCount      = @($allPolicies | Where-Object { $_.State -eq 'disabled' }).Count

Write-Host "  Total policies found        : $($allPolicies.Count)" -ForegroundColor White
Write-Host "  Enforced (State=enabled)    : $($enforcedPolicies.Count)" -ForegroundColor Green
Write-Host "  Report-only (not enforced)  : $($reportOnlyPolicies.Count)" -ForegroundColor Yellow
Write-Host "  Disabled (ignored)          : $disabledCount" -ForegroundColor DarkGray

$userScopedEnforced   = @($enforcedPolicies   | Where-Object { $_.Conditions.Users })
$userScopedReportOnly = @($reportOnlyPolicies | Where-Object { $_.Conditions.Users })
$spnScopedEnforced    = @($enforcedPolicies   | Where-Object { $_.Conditions.ClientApplications })
$spnScopedReportOnly  = @($reportOnlyPolicies | Where-Object { $_.Conditions.ClientApplications })

if ($spnScopedEnforced.Count -eq 0 -and $spnScopedReportOnly.Count -eq 0) {
    Write-Host "  No workload identity (client application) policies found — every service" -ForegroundColor Yellow
    Write-Host "  principal will show as RED unless you add one. This usually means Entra ID" -ForegroundColor Yellow
    Write-Host "  Workload Identities Premium has not been configured yet." -ForegroundColor Yellow
}

# ── Pull users ────────────────────────────────────────────────────────────────
Write-Host "`nRetrieving users..." -ForegroundColor Cyan
$users = Get-MgUser -All -Filter "accountEnabled eq true" -Property Id, DisplayName, UserPrincipalName, UserType, AccountEnabled |
    Select-Object Id, DisplayName, UserPrincipalName, UserType

Write-Host "  Enabled users found          : $($users.Count)" -ForegroundColor White

# ── Evaluate coverage per user ────────────────────────────────────────────────
Write-Host "`nEvaluating Conditional Access coverage per user..." -ForegroundColor Cyan
$userResults = [System.Collections.Generic.List[PSObject]]::new()
$i = 0

foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Checking coverage" -Status "$i of $($users.Count): $($user.UserPrincipalName)" `
        -PercentComplete (($i / [math]::Max($users.Count,1)) * 100)

    $enforcedHits = @()
    foreach ($policy in $userScopedEnforced) {
        if (Test-UserCoveredByPolicy -Policy $policy -UserId $user.Id -UserType $user.UserType) {
            $enforcedHits += $policy.DisplayName
        }
    }

    $reportOnlyHits = @()
    foreach ($policy in $userScopedReportOnly) {
        if (Test-UserCoveredByPolicy -Policy $policy -UserId $user.Id -UserType $user.UserType) {
            $reportOnlyHits += $policy.DisplayName
        }
    }

    if ($enforcedHits.Count -gt 0) {
        $status = 'GREEN'
    }
    elseif ($reportOnlyHits.Count -gt 0) {
        $status = 'AMBER'
    }
    else {
        $status = 'RED'
    }

    $userResults.Add([PSCustomObject]@{
        IdentityType     = 'User'
        DisplayName      = $user.DisplayName
        Identifier       = $user.UserPrincipalName
        UserType         = $user.UserType
        Status           = $status
        EnforcedPolicies = ($enforcedHits -join '; ')
        ReportOnlyOnly   = ($reportOnlyHits -join '; ')
    })
}
Write-Progress -Activity "Checking coverage" -Completed

# ── Evaluate coverage per service principal (workload identities) ────────────
$spnResults = [System.Collections.Generic.List[PSObject]]::new()

if (-not $SkipServicePrincipals) {
    Write-Host "`nRetrieving service principals (workload identities)..." -ForegroundColor Cyan
    # Enterprise apps only — skip Microsoft first-party service principals to
    # keep the report focused on identities your team actually owns.
    $servicePrincipals = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, ServicePrincipalType, AccountEnabled |
        Where-Object { $_.AccountEnabled -and $_.ServicePrincipalType -eq 'Application' }

    Write-Host "  Application service principals found : $($servicePrincipals.Count)" -ForegroundColor White
    Write-Host "`nEvaluating workload identity coverage..." -ForegroundColor Cyan

    $j = 0
    foreach ($spn in $servicePrincipals) {
        $j++
        Write-Progress -Activity "Checking workload identity coverage" `
            -Status "$j of $($servicePrincipals.Count): $($spn.DisplayName)" `
            -PercentComplete (($j / [math]::Max($servicePrincipals.Count,1)) * 100)

        $enforcedHits = @()
        foreach ($policy in $spnScopedEnforced) {
            if (Test-ServicePrincipalCoveredByPolicy -Policy $policy -ServicePrincipalId $spn.Id) {
                $enforcedHits += $policy.DisplayName
            }
        }

        $reportOnlyHits = @()
        foreach ($policy in $spnScopedReportOnly) {
            if (Test-ServicePrincipalCoveredByPolicy -Policy $policy -ServicePrincipalId $spn.Id) {
                $reportOnlyHits += $policy.DisplayName
            }
        }

        if ($enforcedHits.Count -gt 0)      { $status = 'GREEN' }
        elseif ($reportOnlyHits.Count -gt 0) { $status = 'AMBER' }
        else                                  { $status = 'RED' }

        $spnResults.Add([PSCustomObject]@{
            IdentityType     = 'ServicePrincipal'
            DisplayName      = $spn.DisplayName
            Identifier       = $spn.AppId
            UserType         = 'Workload'
            Status           = $status
            EnforcedPolicies = ($enforcedHits -join '; ')
            ReportOnlyOnly   = ($reportOnlyHits -join '; ')
        })
    }
    Write-Progress -Activity "Checking workload identity coverage" -Completed
}

# ── Combine and summarise ──────────────────────────────────────────────────────
$allResults = [System.Collections.Generic.List[PSObject]]::new()
$allResults.AddRange($userResults)
$allResults.AddRange($spnResults)

$redCount   = @($allResults | Where-Object { $_.Status -eq 'RED' }).Count
$amberCount = @($allResults | Where-Object { $_.Status -eq 'AMBER' }).Count
$greenCount = @($allResults | Where-Object { $_.Status -eq 'GREEN' }).Count
$totalCount = $allResults.Count
$coveragePct = if ($totalCount -gt 0) { [math]::Round(($greenCount / $totalCount) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  CONDITIONAL ACCESS COVERAGE GAP AUDIT - $(Get-Date -Format 'dd MMM yyyy HH:mm')" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Identities scanned            : $totalCount" -ForegroundColor White
Write-Host "  GREEN  (enforced coverage)     : $greenCount" -ForegroundColor Green
Write-Host "  AMBER  (report-only only)      : $amberCount" -ForegroundColor Yellow
Write-Host "  RED    (zero applicable policy): $redCount" -ForegroundColor $(if ($redCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Enforced coverage              : $coveragePct%" -ForegroundColor $(if ($coveragePct -ge 99) { 'Green' } elseif ($coveragePct -ge 90) { 'Yellow' } else { 'Red' })
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

if ($redCount -gt 0) {
    Write-Host "RED identities (no enforced Conditional Access policy applies):" -ForegroundColor Red
    $allResults | Where-Object { $_.Status -eq 'RED' } |
        Format-Table IdentityType, DisplayName, Identifier, UserType -AutoSize
}

if ($amberCount -gt 0) {
    Write-Host "AMBER identities (covered ONLY by report-only policies — not enforced):" -ForegroundColor Yellow
    $allResults | Where-Object { $_.Status -eq 'AMBER' } |
        Format-Table IdentityType, DisplayName, Identifier, ReportOnlyOnly -AutoSize
}

# ── Optional CSV export ───────────────────────────────────────────────────────
if ($ExportCsv) {
    $allResults | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "Full result set exported to: $ExportCsv" -ForegroundColor Cyan
}
else {
    Write-Host "Tip: re-run with -ExportCsv `"C:\Reports\ca-coverage-gap.csv`" to save the full result set." -ForegroundColor DarkGray
}

if ($redCount -gt 0) {
    Write-Host "`nACTION: build a true catch-all policy (All users / All cloud apps) with a" -ForegroundColor Yellow
    Write-Host "tightly scoped break-glass exclusion group, add a separate workload identity" -ForegroundColor Yellow
    Write-Host "policy for service principals, then re-run this script to confirm 0 RED." -ForegroundColor Yellow
}
else {
    Write-Host "`nNo zero-coverage identities found in this pass. Re-run periodically — new" -ForegroundColor Green
    Write-Host "users, new app registrations, and group membership changes can reopen gaps." -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null
