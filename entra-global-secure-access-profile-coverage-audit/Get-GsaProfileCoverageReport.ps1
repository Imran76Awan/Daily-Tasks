#Requires -Version 5.1
<#
.SYNOPSIS
    Report-only audit of Microsoft Entra Global Secure Access (GSA) traffic
    forwarding profiles and the policies linked to them. Flags disabled or
    empty profiles that leave a traffic class egressing directly instead of
    being acquired (tunnelled) by Global Secure Access.

.DESCRIPTION
    When an organisation "turns on" Global Secure Access, it is easy to assume
    that all traffic is now tunnelled and inspected. It is not. Traffic is only
    acquired by GSA when a matching traffic forwarding profile is ENABLED and
    at least one ENABLED forwarding policy inside it matches the destination.
    Per Microsoft's own documentation, "Any traffic that doesn't match these
    three profiles isn't forwarded to Global Secure Access" and, in Microsoft's
    documented example response, the Internet access and Private access profiles
    ship DISABLED by default while only the Microsoft 365 profile is enabled.

    This script connects to Microsoft Graph (beta), enumerates the three traffic
    forwarding profiles (m365 / internet / private) with their linked policies,
    and reports:
      - which profiles are ENABLED vs DISABLED (a disabled profile means that
        whole traffic class egresses directly and is never inspected);
      - profiles that are enabled but carry NO policies, or whose policy links
        are all disabled (enabled but acquiring nothing);
      - the case where ALL profiles are disabled (the GSA client receives an
        empty policy - "Your organization disabled the client");
      - whether the expected internet and private profiles are present at all.

    The script is STRICTLY READ-ONLY. It never creates, modifies, deletes,
    enables, disables, resets, or remediates anything. It only reads and reports.

    NOTE: The networkAccess Graph namespace and the
    Get-MgBetaNetworkAccessForwardingProfile cmdlet are in the Microsoft Graph
    BETA endpoint (module Microsoft.Graph.Beta.NetworkAccess). Beta APIs are
    subject to change and are not supported for production use by Microsoft.

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate (installed in the current user or
    local machine store) used for app-only auth.

.PARAMETER UseDeviceCode
    Use interactive device-code sign-in with the delegated least-privilege
    scope NetworkAccess.Read.All instead of app-only certificate auth.

.PARAMETER ExportCsv
    If set, writes the per-profile findings to a CSV file.

.PARAMETER CsvPath
    Destination path for the CSV. Defaults to a timestamped file in the current
    directory when -ExportCsv is supplied without a path.

.EXAMPLE
    .\Get-GsaProfileCoverageReport.ps1 -UseDeviceCode
    Interactive device-code sign-in, then audit and print the coverage report.

.EXAMPLE
    .\Get-GsaProfileCoverageReport.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumbprint>
    App-only certificate auth (unattended), suitable for scheduled runs.

.EXAMPLE
    .\Get-GsaProfileCoverageReport.ps1 -UseDeviceCode -ExportCsv -CsvPath C:\Temp\gsa-coverage.csv
    Audit and also export the per-profile findings to CSV.

.NOTES
    Author      : Imran Awan (EndpointWeekly)
    Requires    : Microsoft.Graph.Beta.NetworkAccess (and Microsoft.Graph.Authentication)
    Scope       : NetworkAccess.Read.All (least-privilege READ scope)
    Exit codes  : 0 = clean (all three profiles enabled and carrying enabled policies)
                  1 = script or Graph query error (fail loud - never reports "healthy")
                  2 = coverage findings detected (disabled / empty / missing profiles)
    Read-only   : This script makes NO changes to any profile, policy, or tenant setting.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$ExportCsv,

    [Parameter()]
    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fail-loud state. Any Graph/query error flips this so the script exits 1 and
# never prints a clean-looking "all healthy" report after a failed query.
$script:hadError = $false

$RequiredScope = 'NetworkAccess.Read.All'
$ExpectedTypes = @('m365', 'internet', 'private')

function Write-Section {
    param([string]$Text)
    $bar = ('=' * 64)
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor DarkCyan
}

function Connect-Graph {
    # Ensure the modules are available before attempting to connect.
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "Module 'Microsoft.Graph.Authentication' is not installed. Install with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Beta.NetworkAccess')) {
        throw "Module 'Microsoft.Graph.Beta.NetworkAccess' is not installed. Install with: Install-Module Microsoft.Graph.Beta.NetworkAccess -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
    Import-Module Microsoft.Graph.Beta.NetworkAccess -ErrorAction Stop | Out-Null

    if ($UseDeviceCode) {
        Write-Host "Connecting to Microsoft Graph (device-code, delegated $RequiredScope)..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $RequiredScope -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        if (-not $TenantId -or -not $ClientId -or -not $CertificateThumbprint) {
            throw "App-only auth requires -TenantId, -ClientId, and -CertificateThumbprint. Alternatively use -UseDeviceCode for interactive sign-in."
        }
        Write-Host "Connecting to Microsoft Graph (app-only certificate auth)..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
    }

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Connect-MgGraph reported success but no Graph context is present."
    }
    Write-Host ("Connected. Tenant: {0}" -f $ctx.TenantId) -ForegroundColor Green
    return $ctx
}

function Get-ForwardingProfiles {
    # Read the forwarding profiles with their linked policies expanded.
    # A failure here is a real problem - surface it and flip the error flag.
    try {
        $profiles = Get-MgBetaNetworkAccessForwardingProfile -ExpandProperty 'policies' -All -ErrorAction Stop
    }
    catch {
        Write-Error ("Graph query for forwarding profiles failed: {0}" -f $_.Exception.Message)
        $script:hadError = $true
        return $null
    }
    return $profiles
}

# --------------------------- main -----------------------------------------

$findings = New-Object System.Collections.Generic.List[object]

try {
    Connect-Graph | Out-Null
}
catch {
    Write-Error ("Authentication/module setup failed: {0}" -f $_.Exception.Message)
    exit 1
}

Write-Host "Enumerating Global Secure Access traffic forwarding profiles..." -ForegroundColor Cyan
$profiles = Get-ForwardingProfiles

if ($script:hadError) {
    Write-Error "One or more Graph queries failed. Report is INCOMPLETE - not reporting health status."
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

Write-Host ""
Write-Section ("GSA PROFILE COVERAGE REPORT - " + (Get-Date -Format 'dd MMM yyyy HH:mm'))

# Handle the case where GSA returns no profiles at all.
if (-not $profiles -or @($profiles).Count -eq 0) {
    Write-Host "  No forwarding profiles returned." -ForegroundColor Yellow
    Write-Host "  Global Secure Access is not onboarded/licensed, or no profiles exist." -ForegroundColor Yellow
    Write-Host "  NOTHING is being acquired by GSA - all traffic egresses directly." -ForegroundColor Red
    $findings.Add([pscustomobject]@{
            ProfileName            = '(none)'
            TrafficForwardingType  = '(none)'
            State                  = '(none)'
            Priority               = ''
            PolicyLinkCount        = 0
            EnabledPolicyLinkCount = 0
            Severity               = 'HIGH'
            Finding                = 'No forwarding profiles found - GSA not configured or not licensed'
        })
}
else {
    $profileArr = @($profiles)
    Write-Host ("  Forwarding profiles found : {0}" -f $profileArr.Count)
    Write-Host ""

    $enabledProfileCount = 0

    foreach ($p in $profileArr) {
        # Property names are PascalCase on the SDK object.
        $name  = $p.Name
        $type  = $p.TrafficForwardingType
        $state = $p.State
        $prio  = $p.Priority

        $links = @()
        if ($p.PSObject.Properties.Name -contains 'Policies' -and $p.Policies) {
            $links = @($p.Policies)
        }
        $linkCount = $links.Count
        $enabledLinks = @($links | Where-Object { $_.State -eq 'enabled' })
        $enabledLinkCount = $enabledLinks.Count

        if ($state -eq 'enabled') { $enabledProfileCount++ }

        # Classify.
        $severity = 'OK'
        $finding  = 'Enabled and carrying at least one enabled policy'

        if ($state -ne 'enabled') {
            $severity = 'HIGH'
            $finding  = ("Profile DISABLED - '{0}' traffic is NOT acquired by GSA (egresses directly, uninspected)" -f $type)
        }
        elseif ($linkCount -eq 0) {
            $severity = 'MEDIUM'
            $finding  = 'Profile enabled but has NO linked policies - no traffic matched or acquired'
        }
        elseif ($enabledLinkCount -eq 0) {
            $severity = 'MEDIUM'
            $finding  = ("Profile enabled but ALL {0} linked policies are disabled - nothing acquired" -f $linkCount)
        }

        $color = switch ($severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Green' } }

        Write-Host ("  Profile   : {0}" -f $name)
        Write-Host ("  Type      : {0}" -f $type)
        Write-Host ("  State     : {0}" -f $state) -ForegroundColor $color
        Write-Host ("  Priority  : {0}" -f $prio)
        Write-Host ("  Policies  : {0} linked, {1} enabled" -f $linkCount, $enabledLinkCount)
        Write-Host ("  Result    : [{0}] {1}" -f $severity, $finding) -ForegroundColor $color
        Write-Host ""

        if ($severity -ne 'OK') {
            $findings.Add([pscustomobject]@{
                    ProfileName            = $name
                    TrafficForwardingType  = $type
                    State                  = $state
                    Priority               = $prio
                    PolicyLinkCount        = $linkCount
                    EnabledPolicyLinkCount = $enabledLinkCount
                    Severity               = $severity
                    Finding                = $finding
                })
        }
    }

    # All profiles disabled => GSA client receives an empty policy.
    if ($enabledProfileCount -eq 0) {
        Write-Host "  WARNING: EVERY forwarding profile is disabled." -ForegroundColor Red
        Write-Host "  The GSA client will receive an empty policy ('Your organization disabled the client')." -ForegroundColor Red
        Write-Host ""
        $findings.Add([pscustomobject]@{
                ProfileName            = '(all)'
                TrafficForwardingType  = '(all)'
                State                  = 'disabled'
                Priority               = ''
                PolicyLinkCount        = ''
                EnabledPolicyLinkCount = 0
                Severity               = 'HIGH'
                Finding                = 'All forwarding profiles disabled - GSA client receives an empty policy'
            })
    }

    # Report on expected traffic types that are missing entirely.
    $presentTypes = @($profileArr | ForEach-Object { $_.TrafficForwardingType })
    foreach ($t in $ExpectedTypes) {
        if ($presentTypes -notcontains $t) {
            Write-Host ("  NOTE: no '{0}' traffic forwarding profile is present in this tenant." -f $t) -ForegroundColor Yellow
            $findings.Add([pscustomobject]@{
                    ProfileName            = ("(missing {0})" -f $t)
                    TrafficForwardingType  = $t
                    State                  = '(absent)'
                    Priority               = ''
                    PolicyLinkCount        = 0
                    EnabledPolicyLinkCount = 0
                    Severity               = 'MEDIUM'
                    Finding                = ("No '{0}' traffic forwarding profile present - that traffic class cannot be acquired" -f $t)
                })
        }
    }
}

Write-Section "SUMMARY"
$findingCount = $findings.Count
if ($findingCount -eq 0) {
    Write-Host "  STATUS: CLEAN - all three profiles enabled and carrying enabled policies." -ForegroundColor Green
}
else {
    Write-Host ("  STATUS: {0} coverage finding(s) detected - review before trusting GSA coverage." -f $findingCount) -ForegroundColor Red
    foreach ($f in $findings) {
        Write-Host ("   [{0}] {1} ({2}): {3}" -f $f.Severity, $f.ProfileName, $f.TrafficForwardingType, $f.Finding) -ForegroundColor Yellow
    }
}
Write-Host ("=" * 64) -ForegroundColor DarkCyan

# CSV export (findings only).
if ($ExportCsv) {
    if (-not $CsvPath) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("GsaProfileCoverage_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    try {
        if ($findingCount -eq 0) {
            [pscustomobject]@{
                ProfileName            = '(none)'
                TrafficForwardingType  = '(none)'
                State                  = '(none)'
                Priority               = ''
                PolicyLinkCount        = ''
                EnabledPolicyLinkCount = ''
                Severity               = 'OK'
                Finding                = 'No coverage findings'
            } | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        }
        else {
            $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        }
        Write-Host ("CSV written: {0}" -f $CsvPath) -ForegroundColor Green
    }
    catch {
        Write-Error ("Failed to write CSV to '{0}': {1}" -f $CsvPath, $_.Exception.Message)
        $script:hadError = $true
    }
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

# Exit codes: 1 = error, 2 = findings, 0 = clean.
if ($script:hadError) { exit 1 }
if ($findingCount -gt 0) { exit 2 }
exit 0
