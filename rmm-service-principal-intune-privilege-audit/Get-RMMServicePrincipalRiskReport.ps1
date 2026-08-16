<#
.SYNOPSIS
    Reports every service principal (enterprise application) in a tenant that holds
    Microsoft Graph application permissions equivalent to an Intune Administrator or
    Entra ID administrator role.

.DESCRIPTION
    Get-RMMServicePrincipalRiskReport.ps1 enumerates every non-Microsoft service
    principal in the tenant using Get-MgServicePrincipal, then retrieves each one's
    granted application permissions with Get-MgServicePrincipalAppRoleAssignment.

    Each service principal is scored against a defined catalog of Graph application
    permissions considered Intune-administrator-equivalent or Entra-administrator-
    equivalent in blast radius (for example DeviceManagementConfiguration.ReadWrite.All,
    DeviceManagementManagedDevices.ReadWrite.All, RoleManagement.ReadWrite.Directory,
    Directory.ReadWrite.All, and Application.ReadWrite.All).

    Permission GUIDs are resolved dynamically at runtime from the Microsoft Graph
    service principal's own AppRoles collection in the connected tenant, rather than
    hardcoded, so the script does not silently break if a GUID differs between
    environments.

    Background: this script exists because Entra ID has no built-in report that
    cross-references every enterprise application's granted Graph permissions against
    a defined high-privilege list in one pass. In May 2025, security researchers
    reported that the DragonForce ransomware group compromised a managed service
    provider through vulnerabilities in its SimpleHelp remote monitoring and
    management (RMM) platform, then used that access to attack the MSP's downstream
    customers. An RMM, MSP-platform, or other third-party service principal holding
    admin-equivalent Graph permissions in your own tenant is exposed to the same class
    of upstream-compromise risk, whether or not that specific vendor was involved.

    This script is READ-ONLY. It only calls Get-Mg* cmdlets (Graph GET requests).
    It never creates, modifies, or removes any object, role assignment, or
    permission grant.

.PARAMETER TenantId
    The Entra ID tenant ID (GUID) or verified domain to connect to. Required when
    using certificate-based app-only authentication.

.PARAMETER ClientId
    The application (client) ID of the app registration used for app-only
    authentication. Required when using certificate-based authentication.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate installed in the local certificate store,
    used for app-only authentication together with -TenantId and -ClientId.

.PARAMETER UseDeviceCode
    Switch. Falls back to interactive device-code sign-in instead of certificate
    app-only authentication. Useful for a one-off run from an admin workstation
    without a registered app or certificate in place.

.PARAMETER StaleSignInDays
    Number of days since a service principal's last sign-in (from Entra ID sign-in
    logs) after which an admin-equivalent finding is escalated from AMBER to RED,
    on the basis that a dormant high-privilege identity is a higher-priority risk
    than an actively-used one. Default is 90.

.PARAMETER ShowAllFindings
    Switch. Lists every scanned service principal in the console output, including
    GREEN (no admin-equivalent permissions found). Without this switch, only RED
    and AMBER findings are listed individually and GREEN results are summarised
    as a single count.

.PARAMETER ExportCsv
    Switch. Exports the full findings table to a CSV file.

.PARAMETER CsvPath
    Path for the CSV export when -ExportCsv is used. Defaults to
    .\RMMServicePrincipalRiskReport_<timestamp>.csv in the current directory.

.EXAMPLE
    .\Get-RMMServicePrincipalRiskReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "{aaaaaaaa-0b0b-1c1c-2d2d-333333333333}" -CertificateThumbprint "A1B2C3D4E5F6..."

    Runs the audit using app-only certificate authentication and prints RED/AMBER
    findings to the console.

.EXAMPLE
    .\Get-RMMServicePrincipalRiskReport.ps1 -UseDeviceCode -ExportCsv -ShowAllFindings

    Runs the audit interactively via device code sign-in, prints every service
    principal scanned (including GREEN), and exports the full results to CSV.

.NOTES
    Author        : Imran Awan
    Blog post     : https://endpointweekly.com/blog/rmm-service-principal-intune-privilege-audit.html
    Requires      : Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication PowerShell modules
    Required Graph scopes (delegated or application): Application.Read.All, Directory.Read.All, AuditLog.Read.All
    Exit codes    : 0 = clean (no RED or AMBER findings), 1 = findings present, 2 = error
    This script performs READ-ONLY Graph GET operations only. It makes no changes
    to any tenant object. Validate in your own non-production environment before
    relying on its output operationally.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [int]$StaleSignInDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$ShowAllFindings,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Catalog of Graph APPLICATION permissions considered Intune-administrator or
# Entra-administrator equivalent in blast radius. Verified against the
# Microsoft Graph permissions reference (learn.microsoft.com/graph/permissions-reference).
# Key = permission name (AppRole Value on the Microsoft Graph service principal).
# ---------------------------------------------------------------------------
$script:IntuneEntraAdminEquivalentScopes = @(
    'RoleManagement.ReadWrite.Directory',
    'Directory.ReadWrite.All',
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementManagedDevices.ReadWrite.All',
    'DeviceManagementApps.ReadWrite.All',
    'DeviceManagementRBAC.ReadWrite.All',
    'Device.ReadWrite.All'
)

# Name/domain hints used ONLY to help you triage the CSV faster. This does not
# affect severity scoring - an over-permissioned internal app is just as
# dangerous as an over-permissioned vendor app.
$script:RmmNameHints = @(
    'rmm', 'remote', 'monitor', 'msp', 'agent', 'connectwise', 'kaseya',
    'datto', 'ninjaone', 'ninja one', 'atera', 'n-able', 'nable', 'syncro',
    'simplehelp', 'screenconnect', 'teamviewer', 'splashtop'
)

# Well-known tenant ID Microsoft uses to own its own first-party service
# principals (Microsoft Graph, Office 365, etc). Used to exclude first-party
# noise from the report.
$script:MicrosoftFirstPartyTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

function Connect-ToGraph {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceCode
    )

    $requiredScopes = @('Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All')

    try {
        if ($UseDeviceCode) {
            Write-Host "[INFO] Connecting to Microsoft Graph using device code sign-in..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication | Out-Null
        }
        elseif ($TenantId -and $ClientId -and $CertificateThumbprint) {
            Write-Host "[INFO] Connecting to Microsoft Graph using app-only certificate authentication..." -ForegroundColor Cyan
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint | Out-Null
        }
        else {
            throw "Provide -TenantId, -ClientId and -CertificateThumbprint for app-only auth, or pass -UseDeviceCode for interactive sign-in."
        }
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 2
    }
}

function Resolve-HighRiskPermissionLookup {
    Write-Host "[INFO] Resolving Intune/Entra admin-equivalent scope catalog to GUIDs for this tenant..." -ForegroundColor Cyan

    try {
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Property Id, AppId, AppRoles -ErrorAction Stop
    }
    catch {
        Write-Error "Could not resolve the Microsoft Graph service principal in this tenant: $($_.Exception.Message)"
        exit 2
    }

    if (-not $graphSp) {
        Write-Error "Microsoft Graph service principal (appId 00000003-0000-0000-c000-000000000000) was not found in this tenant."
        exit 2
    }

    $lookup = @{}
    foreach ($permName in $script:IntuneEntraAdminEquivalentScopes) {
        $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
        if ($role) {
            $lookup[$role.Id.ToString()] = $permName
        }
        else {
            Write-Warning "Permission '$permName' was not found on the Microsoft Graph AppRoles collection in this tenant - it may have been renamed or retired. Skipping."
        }
    }

    Write-Host "Resolved $($lookup.Count) application-permission GUIDs from the high-risk catalog." -ForegroundColor Gray
    return $lookup
}

function Get-LastSignInDaysAgo {
    param([string]$ServicePrincipalObjectId)

    try {
        $filter = "appId eq '$ServicePrincipalObjectId'"
        $signIns = Get-MgAuditLogSignIn -Filter $filter -Top 1 -Sort "createdDateTime desc" -ErrorAction Stop
        if ($signIns -and $signIns.Count -gt 0) {
            $lastSignIn = $signIns[0].CreatedDateTime
            return [int]((Get-Date).ToUniversalTime() - $lastSignIn).TotalDays
        }
    }
    catch {
        # Sign-in log queries can fail on tenants without Entra ID P1/P2 licensing,
        # or if AuditLog.Read.All wasn't consented. Treat as unknown rather than fatal.
        return $null
    }
    return $null
}

function Get-ServicePrincipalFindings {
    param([hashtable]$HighRiskLookup, [int]$StaleSignInDays)

    Write-Host ""
    Write-Host "Enumerating service principals... this can take a few minutes in large tenants." -ForegroundColor Gray

    try {
        $allServicePrincipals = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, PublisherName, VerifiedPublisher, AppOwnerOrganizationId -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to enumerate service principals: $($_.Exception.Message)"
        exit 2
    }

    $nonMicrosoftSps = $allServicePrincipals | Where-Object {
        $_.AppOwnerOrganizationId -ne $script:MicrosoftFirstPartyTenantId
    }

    Write-Host "Found $($allServicePrincipals.Count) total service principals, $($nonMicrosoftSps.Count) after excluding first-party Microsoft apps." -ForegroundColor Gray
    Write-Host ""

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($sp in $nonMicrosoftSps) {

        $grantedHighRisk = New-Object System.Collections.Generic.List[string]

        try {
            $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not read app role assignments for '$($sp.DisplayName)' ($($sp.Id)): $($_.Exception.Message)"
            continue
        }

        foreach ($assignment in $appRoleAssignments) {
            $roleId = $assignment.AppRoleId.ToString()
            if ($HighRiskLookup.ContainsKey($roleId)) {
                $permName = $HighRiskLookup[$roleId]
                if (-not $grantedHighRisk.Contains($permName)) {
                    $grantedHighRisk.Add($permName) | Out-Null
                }
            }
        }

        $isVerifiedPublisher = ($null -ne $sp.VerifiedPublisher) -and
            (-not [string]::IsNullOrWhiteSpace($sp.VerifiedPublisher.DisplayName))

        $looksLikeRmm = $false
        foreach ($hint in $script:RmmNameHints) {
            if ($sp.DisplayName -and $sp.DisplayName.ToLowerInvariant().Contains($hint)) {
                $looksLikeRmm = $true
                break
            }
        }

        $daysSinceLastSignIn = $null
        $severity = 'GREEN'

        if ($grantedHighRisk.Count -gt 0) {
            $daysSinceLastSignIn = Get-LastSignInDaysAgo -ServicePrincipalObjectId $sp.AppId

            $isStaleOrUnknown = ($null -eq $daysSinceLastSignIn) -or ($daysSinceLastSignIn -gt $StaleSignInDays)

            if ($isStaleOrUnknown -or -not $isVerifiedPublisher) {
                $severity = 'RED'
            }
            else {
                $severity = 'AMBER'
            }
        }

        $findings.Add([PSCustomObject]@{
            DisplayName          = $sp.DisplayName
            AppId                = $sp.AppId
            Severity             = $severity
            HighRiskPermissions  = ($grantedHighRisk -join '; ')
            VerifiedPublisher    = $isVerifiedPublisher
            PublisherName        = $sp.PublisherName
            LooksLikeRmmOrMsp    = $looksLikeRmm
            DaysSinceLastSignIn  = $daysSinceLastSignIn
        }) | Out-Null
    }

    return $findings
}

function Write-FindingsReport {
    param([System.Collections.Generic.List[object]]$Findings, [switch]$ShowAllFindings)

    Write-Host "=== RMM / Third-Party Service Principal Privilege Report ===" -ForegroundColor White
    Write-Host ""

    $redFindings = $Findings | Where-Object { $_.Severity -eq 'RED' }
    $amberFindings = $Findings | Where-Object { $_.Severity -eq 'AMBER' }
    $greenFindings = $Findings | Where-Object { $_.Severity -eq 'GREEN' }

    foreach ($finding in $redFindings) {
        $signInText = if ($null -eq $finding.DaysSinceLastSignIn) { "unknown" } else { "$($finding.DaysSinceLastSignIn) days ago" }
        Write-Host "[RED  ] $($finding.DisplayName)  Publisher: $(if ($finding.VerifiedPublisher) {'Verified'} else {'Not verified'})  Last sign-in: $signInText" -ForegroundColor Red
        Write-Host "        $($finding.HighRiskPermissions)" -ForegroundColor Red
    }

    foreach ($finding in $amberFindings) {
        $signInText = if ($null -eq $finding.DaysSinceLastSignIn) { "unknown" } else { "$($finding.DaysSinceLastSignIn) days ago" }
        Write-Host "[AMBER] $($finding.DisplayName)  Publisher: $(if ($finding.VerifiedPublisher) {'Verified'} else {'Not verified'})  Last sign-in: $signInText" -ForegroundColor Yellow
        Write-Host "        $($finding.HighRiskPermissions)" -ForegroundColor Yellow
    }

    if ($ShowAllFindings) {
        foreach ($finding in $greenFindings) {
            Write-Host "[GREEN] $($finding.DisplayName) - no admin-equivalent scopes found" -ForegroundColor Green
        }
    }
    else {
        Write-Host "[GREEN] $($greenFindings.Count) other service principals - no admin-equivalent scopes found" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "--- Summary ---"
    Write-Host "Total service principals scanned            : $($Findings.Count)"
    Write-Host "RED   (admin-equiv scope, stale/unverified)  : $($redFindings.Count)" -ForegroundColor Red
    Write-Host "AMBER (admin-equiv scope, active+verified)   : $($amberFindings.Count)" -ForegroundColor Yellow
    Write-Host "GREEN (no admin-equivalent scopes)           : $($greenFindings.Count)" -ForegroundColor Green
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    Connect-ToGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -UseDeviceCode:$UseDeviceCode

    $highRiskLookup = Resolve-HighRiskPermissionLookup

    $findings = Get-ServicePrincipalFindings -HighRiskLookup $highRiskLookup -StaleSignInDays $StaleSignInDays

    Write-FindingsReport -Findings $findings -ShowAllFindings:$ShowAllFindings

    if ($ExportCsv) {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $CsvPath = ".\RMMServicePrincipalRiskReport_$timestamp.csv"
        }
        $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[INFO] Full findings exported to $CsvPath" -ForegroundColor Cyan
    }

    Write-Host "[INFO] Report complete."

    $riskyCount = ($findings | Where-Object { $_.Severity -in @('RED', 'AMBER') }).Count
    if ($riskyCount -gt 0) {
        exit 1
    }
    else {
        exit 0
    }
}
catch {
    Write-Error "Unhandled error: $($_.Exception.Message)"
    exit 2
}
finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# Reference syntax for removing a permission grant once confirmed unnecessary
# (NOT executed by this script - this file is read-only):
#
# Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <spObjectId> -AppRoleAssignmentId <assignmentId>
