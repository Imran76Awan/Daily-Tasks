#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Read-only audit of Microsoft Entra cross-tenant access INBOUND TRUST settings.

.DESCRIPTION
    Reports which cross-tenant access configurations trust inbound Conditional Access
    claims (MFA, compliant device, Microsoft Entra hybrid joined device) from external
    Microsoft Entra organizations.

    Why this matters: if your Conditional Access policy requires MFA for guests but an
    inbound trust setting accepts an MFA claim that a guest already satisfied in THEIR
    home tenant, a user from a partner with weaker MFA can pass your MFA requirement
    without ever being challenged in your tenant. The trust can be set on the tenant-wide
    DEFAULT configuration (which then applies to every partner you have not explicitly
    overridden) or on an individual PARTNER configuration.

    The script:
      1. Reads the default cross-tenant access configuration.
      2. Enumerates every partner-specific configuration (all pages).
      3. Resolves each partner's EFFECTIVE inbound trust. A partner property that is
         null inherits the default value (per Microsoft Graph documentation); the script
         resolves that inheritance rather than skipping it.
      4. Flags the default and any partner where isMfaAccepted,
         isCompliantDeviceAccepted, or isHybridAzureADJoinedDeviceAccepted is effectively
         true, and reports partners by tenantId.

    This script is REPORT-ONLY. It never creates, modifies, deletes, enables, disables,
    or resets any cross-tenant access policy, partner configuration, or trust setting.
    It connects with the least-privilege READ scope Policy.Read.All, which cannot write
    policy. Remediation (unticking a trust checkbox or scoping it to a specific partner)
    is a deliberate change you make yourself in the Microsoft Entra admin center.

    Verified against Microsoft Learn:
      - Get-MgPolicyCrossTenantAccessPolicyDefault / -Partner: module
        Microsoft.Graph.Identity.SignIns; least-privilege scope Policy.Read.All.
      - crossTenantAccessPolicyInboundTrust properties: isMfaAccepted,
        isCompliantDeviceAccepted, isHybridAzureADJoinedDeviceAccepted (all Boolean).
      - crossTenantAccessPolicyConfigurationPartner: "For any partner-specific property
        that is null, these settings inherit the behavior configured in your default
        cross-tenant access settings."

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only certificate
    authentication. The app must hold the Policy.Read.All APPLICATION permission.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (present in the current user or local machine store)
    used for app-only authentication.

.PARAMETER UseDeviceCode
    Use interactive device code sign-in instead of app-only certificate auth. The signed-in
    account needs the delegated Policy.Read.All permission (read-only).

.PARAMETER ExportCsv
    Also write the findings to a CSV file.

.PARAMETER CsvPath
    Path for the CSV output. Defaults to a timestamped file in the current directory.

.EXAMPLE
    .\Get-CrossTenantInboundTrustReport.ps1 -UseDeviceCode

    Interactive read-only run. Prompts for device code sign-in, then reports every
    configuration that trusts inbound MFA or device claims.

.EXAMPLE
    .\Get-CrossTenantInboundTrustReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "1111...aaaa" -CertificateThumbprint "AB12...CD34"

    Unattended app-only run using certificate authentication (for a scheduled task or
    Azure Automation runbook).

.EXAMPLE
    .\Get-CrossTenantInboundTrustReport.ps1 -UseDeviceCode -ExportCsv -CsvPath "C:\Reports\xtap-trust.csv"

    Interactive run that also exports the findings to a CSV file for evidence.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Exit codes:
        0 = clean - no configuration trusts inbound MFA/device claims
        1 = script or Graph query error (results are NOT reliable)
        2 = findings detected - at least one configuration trusts inbound claims
    Report-only. ASCII-only. Requires the Microsoft Graph PowerShell SDK.
#>

[CmdletBinding(DefaultParameterSetName = 'DeviceCode')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnly')]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnly')]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppOnly')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$ExportCsv,

    [Parameter()]
    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:hadError = $false
$RequiredScope   = 'Policy.Read.All'

function Write-Section {
    param([string]$Text)
    Write-Host ('=' * 64) -ForegroundColor DarkYellow
    Write-Host ("  " + $Text) -ForegroundColor DarkYellow
    Write-Host ('=' * 64) -ForegroundColor DarkYellow
}

function Write-Rule {
    Write-Host ('-' * 64) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Preflight: confirm required modules are available (fail loud if not).
# ---------------------------------------------------------------------------
foreach ($mod in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "ERROR: Required module '$mod' is not installed." -ForegroundColor Red
        Write-Host "       Install it with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph (read-only).
# ---------------------------------------------------------------------------
try {
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop | Out-Null

    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Write-Host "Connecting to Microsoft Graph (app-only certificate auth)..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host "Connecting to Microsoft Graph (interactive device code)..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $RequiredScope -UseDeviceCode -NoWelcome -ErrorAction Stop
    }

    $ctx = Get-MgContext -ErrorAction Stop
    if ($null -eq $ctx) { throw "No Microsoft Graph context after connect." }
    Write-Host ("Connected. Tenant: " + $ctx.TenantId) -ForegroundColor Cyan
}
catch {
    Write-Host ("ERROR: Failed to connect to Microsoft Graph: " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Read the DEFAULT cross-tenant access configuration.
# ---------------------------------------------------------------------------
try {
    Write-Host "Reading default cross-tenant access configuration..." -ForegroundColor Cyan
    $default = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop
}
catch {
    Write-Host ("ERROR: Could not read the default cross-tenant access configuration: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host "       Results are not reliable. Exiting without a report." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

# ---------------------------------------------------------------------------
# Enumerate every PARTNER-specific configuration (all pages).
# ---------------------------------------------------------------------------
try {
    Write-Host "Enumerating partner-specific configurations..." -ForegroundColor Cyan
    $partners = @(Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop)
}
catch {
    Write-Host ("ERROR: Could not enumerate partner configurations: " + $_.Exception.Message) -ForegroundColor Red
    Write-Host "       Results are not reliable. Exiting without a report." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

Write-Host ("  Partner configurations found         : " + $partners.Count) -ForegroundColor Gray
Write-Host ""

# ---------------------------------------------------------------------------
# Helper: safely read a nested property that may be null / absent.
# ---------------------------------------------------------------------------
function Get-TrustValue {
    param($TrustObject, [string]$PropertyName)
    if ($null -eq $TrustObject) { return $null }
    if ($TrustObject.PSObject.Properties.Name -contains $PropertyName) {
        return $TrustObject.$PropertyName
    }
    return $null
}

# Default trust values (the baseline every inherited partner falls back to).
$defTrust    = $default.InboundTrust
$defMfa      = [bool](Get-TrustValue $defTrust 'IsMfaAccepted')
$defCompl    = [bool](Get-TrustValue $defTrust 'IsCompliantDeviceAccepted')
$defHybrid   = [bool](Get-TrustValue $defTrust 'IsHybridAzureADJoinedDeviceAccepted')

$results  = New-Object System.Collections.Generic.List[object]
$findings = 0

# ---------------------------------------------------------------------------
# Evaluate the DEFAULT configuration.
# ---------------------------------------------------------------------------
$defaultHasTrust = ($defMfa -or $defCompl -or $defHybrid)
if ($defaultHasTrust) { $findings++ }

$results.Add([pscustomobject]@{
    Scope                               = 'DEFAULT'
    PartnerTenantId                     = '(applies to all inherited partners)'
    Source                              = 'Default configuration'
    IsMfaAccepted                       = $defMfa
    IsCompliantDeviceAccepted           = $defCompl
    IsHybridAzureADJoinedDeviceAccepted = $defHybrid
    TrustsInboundClaims                 = $defaultHasTrust
})

# ---------------------------------------------------------------------------
# Evaluate every PARTNER configuration, resolving inheritance from default.
# ---------------------------------------------------------------------------
foreach ($p in $partners) {
    $pt = $null
    if ($p.PSObject.Properties.Name -contains 'InboundTrust') { $pt = $p.InboundTrust }

    $rawMfa    = Get-TrustValue $pt 'IsMfaAccepted'
    $rawCompl  = Get-TrustValue $pt 'IsCompliantDeviceAccepted'
    $rawHybrid = Get-TrustValue $pt 'IsHybridAzureADJoinedDeviceAccepted'

    # A null partner property inherits the default value.
    $effMfa    = if ($null -ne $rawMfa)    { [bool]$rawMfa }    else { $defMfa }
    $effCompl  = if ($null -ne $rawCompl)  { [bool]$rawCompl }  else { $defCompl }
    $effHybrid = if ($null -ne $rawHybrid) { [bool]$rawHybrid } else { $defHybrid }

    # "Source" reflects whether ANY trust property is set directly on the partner.
    $hasOverride = ($null -ne $rawMfa) -or ($null -ne $rawCompl) -or ($null -ne $rawHybrid)
    $source = if ($hasOverride) { 'Partner-specific override' } else { 'Inherited from default' }

    $partnerHasTrust = ($effMfa -or $effCompl -or $effHybrid)
    if ($partnerHasTrust) { $findings++ }

    $results.Add([pscustomobject]@{
        Scope                               = 'PARTNER'
        PartnerTenantId                     = $p.TenantId
        Source                              = $source
        IsMfaAccepted                       = $effMfa
        IsCompliantDeviceAccepted           = $effCompl
        IsHybridAzureADJoinedDeviceAccepted = $effHybrid
        TrustsInboundClaims                 = $partnerHasTrust
    })
}

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------
$stamp = (Get-Date).ToString('dd MMM yyyy HH:mm')
Write-Section ("CROSS-TENANT INBOUND TRUST REPORT - " + $stamp)

foreach ($r in $results) {
    if ($r.Scope -eq 'DEFAULT') {
        Write-Host "  Scope                : DEFAULT (applies to all inherited partners)"
    }
    else {
        Write-Host ("  PartnerTenantId      : " + $r.PartnerTenantId)
        Write-Host ("  Source               : " + $r.Source)
    }

    $mfaColor    = if ($r.IsMfaAccepted)     { 'Red' } else { 'Green' }
    $complColor  = if ($r.IsCompliantDeviceAccepted) { 'Red' } else { 'Green' }
    $hybridColor = if ($r.IsHybridAzureADJoinedDeviceAccepted) { 'Red' } else { 'Green' }

    Write-Host ("  IsMfaAccepted                        : " + $r.IsMfaAccepted) -ForegroundColor $mfaColor
    Write-Host ("  IsCompliantDeviceAccepted            : " + $r.IsCompliantDeviceAccepted) -ForegroundColor $complColor
    Write-Host ("  IsHybridAzureADJoinedDeviceAccepted  : " + $r.IsHybridAzureADJoinedDeviceAccepted) -ForegroundColor $hybridColor

    if ($r.TrustsInboundClaims) {
        if ($r.Scope -eq 'DEFAULT') {
            Write-Host "  FINDING: default trusts inbound MFA/device claims - widest exposure" -ForegroundColor Red
        }
        elseif ($r.Source -eq 'Inherited from default') {
            Write-Host "  FINDING: inherits inbound trust from default" -ForegroundColor Red
        }
        else {
            Write-Host "  FINDING: partner explicitly trusts inbound MFA/device claims" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  OK: trusts no inbound MFA/device claims" -ForegroundColor Green
    }
    Write-Rule
}

$trustCount = @($results | Where-Object { $_.TrustsInboundClaims }).Count
$cleanCount = $results.Count - $trustCount

Write-Section "SUMMARY"
Write-Host ("  Configurations evaluated   : " + $results.Count + "  (1 default + " + $partners.Count + " partners)")
if ($trustCount -gt 0) {
    Write-Host ("  Configurations with trust  : " + $trustCount) -ForegroundColor Red
}
else {
    Write-Host ("  Configurations with trust  : " + $trustCount) -ForegroundColor Green
}
Write-Host ("  Clean (no inbound trust)   : " + $cleanCount) -ForegroundColor Green
Write-Host ('=' * 64) -ForegroundColor DarkYellow

# ---------------------------------------------------------------------------
# Optional CSV export.
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("CrossTenantInboundTrust_" + (Get-Date).ToString('yyyyMMdd_HHmmss') + ".csv")
    }
    try {
        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ("CSV written to: " + $CsvPath) -ForegroundColor Cyan
    }
    catch {
        Write-Host ("ERROR: Failed to write CSV to '" + $CsvPath + "': " + $_.Exception.Message) -ForegroundColor Red
        $script:hadError = $true
    }
}

# ---------------------------------------------------------------------------
# Disconnect and exit with the appropriate code.
# ---------------------------------------------------------------------------
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

if ($script:hadError) {
    Write-Host "Completed WITH ERRORS - review output above. Exit code 1." -ForegroundColor Red
    exit 1
}
elseif ($findings -gt 0) {
    Write-Host "Findings detected - review inbound trust before your next access review. Exit code 2." -ForegroundColor Yellow
    exit 2
}
else {
    Write-Host "No inbound MFA/device trust configured anywhere. Exit code 0." -ForegroundColor Green
    exit 0
}
