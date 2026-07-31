<#
.SYNOPSIS
    Reports Microsoft Entra ID Protection risk detections that were closed by
    dismissal or auto-remediation inside a lookback window, so an admin can
    re-review risk that has already dropped off the "risky users" report.

.DESCRIPTION
    Entra ID Protection surfaces risky users only while their risk state is
    'atRisk'. The moment a detection is dismissed (an admin action) or
    remediated (for example the user passed MFA driven by a risk-based policy,
    or performed a secured password change/reset), the associated riskState
    flips to 'dismissed' or 'remediated' and the user disappears from the
    "risky users" dashboard - even when the original detection was genuinely
    worth investigating.

    This script queries every risk detection with Get-MgRiskDetection, keeps
    the ones whose riskState is 'dismissed' or 'remediated' and whose
    detectedDateTime falls inside the -Days lookback window, and shows the
    original riskLevel plus the riskDetail (which explains exactly HOW each
    detection was closed and by whom). The intent is to give you back the
    visibility the dashboard hides.

    REPORT-ONLY. This script performs read operations only. It never creates,
    modifies, deletes, dismisses, confirms, remediates, enables, or disables
    anything in the tenant. Its only Graph permission requirement is the
    read-only scope IdentityRiskEvent.Read.All.

    Requires Microsoft Entra ID P2 (Identity Protection) and the
    Microsoft.Graph.Identity.SignIns PowerShell module.

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only
    certificate authentication.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (installed in the current user or local
    machine store) used for app-only certificate authentication.

.PARAMETER UseDeviceCode
    Use interactive device-code sign-in instead of app-only certificate auth.
    Requests the delegated scope IdentityRiskEvent.Read.All. Useful for a quick
    manual run when no app registration/certificate is configured.

.PARAMETER Days
    Lookback window in days, based on each detection's detectedDateTime.
    Valid range 1-90 (Identity Protection retention dependent). Default is 30.

.PARAMETER ExportCsv
    Also write the findings to a CSV file.

.PARAMETER CsvPath
    Destination path for the CSV. If omitted while -ExportCsv is used, a
    timestamped file is written to the current directory.

.EXAMPLE
    .\Get-DismissedRiskDetectionAudit.ps1 -UseDeviceCode

    Interactive run. Signs in with device code and reports every dismissed or
    auto-remediated risk detection from the last 30 days.

.EXAMPLE
    .\Get-DismissedRiskDetectionAudit.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumb> -Days 60 -ExportCsv

    Unattended app-only run over a 60-day window, exporting the findings to a
    timestamped CSV in the current directory.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Cmdlet : Get-MgRiskDetection (module Microsoft.Graph.Identity.SignIns)
    Scope  : IdentityRiskEvent.Read.All (read-only)
    Exit   : 0 = no findings, 1 = script/query error, 2 = findings detected
    This tool is report-only and makes no changes to the tenant.
#>

[CmdletBinding(DefaultParameterSetName = 'DeviceCode')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [ValidateRange(1, 90)]
    [int]$Days = 30,

    [switch]$ExportCsv,

    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

# Read-only scope required to read risk detections.
$RequiredScope = 'IdentityRiskEvent.Read.All'

# Risk states that mean "this detection has been closed and is no longer on the
# active risky-users report". These are the ones we want to resurface.
$ClosedStates = @('dismissed', 'remediated')

# Human-readable explanation of how a detection was closed, keyed on riskDetail.
$RiskDetailLabels = @{
    'adminDismissedAllRiskForUser'          = 'Admin dismissed ALL risk for the user'
    'adminDismissedRiskForSignIn'           = 'Admin dismissed the risk for this sign-in'
    'adminConfirmedSigninSafe'              = 'Admin confirmed the sign-in as safe'
    'adminConfirmedAccountSafe'             = 'Admin confirmed the account as safe'
    'm365DAdminDismissedDetection'          = 'Defender XDR admin dismissed the detection'
    'aiConfirmedSigninSafe'                 = 'AI confirmed the sign-in as safe'
    'userPassedMFADrivenByRiskBasedPolicy'  = 'User self-remediated by passing MFA (risk-based policy)'
    'userPerformedSecuredPasswordChange'    = 'User self-remediated via secure password change'
    'userPerformedSecuredPasswordReset'     = 'User self-remediated via secure password reset'
    'userChangedPasswordOnPremises'         = 'User changed password on-premises (self-remediated)'
    'adminGeneratedTemporaryPassword'       = 'Admin generated a temporary password'
    'microsoftRevokedSessions'              = 'Microsoft revoked the user sessions'
    'none'                                  = 'No detail recorded'
    'hidden'                                = 'Detail hidden'
}

function Write-Line {
    param([string]$Text, [string]$Colour = 'Gray')
    Write-Host $Text -ForegroundColor $Colour
}

function Get-RiskDetailLabel {
    param([string]$Detail)
    if ([string]::IsNullOrWhiteSpace($Detail)) { return 'No detail recorded' }
    if ($RiskDetailLabels.ContainsKey($Detail)) { return $RiskDetailLabels[$Detail] }
    return $Detail
}

function Format-Location {
    param($Location)
    if ($null -eq $Location) { return '' }
    $parts = @()
    foreach ($p in @($Location.City, $Location.State, $Location.CountryOrRegion)) {
        if (-not [string]::IsNullOrWhiteSpace($p)) { $parts += $p }
    }
    return ($parts -join ', ')
}

# --- Confirm the cmdlet is available before doing anything else -------------
if (-not (Get-Command -Name 'Get-MgRiskDetection' -ErrorAction SilentlyContinue)) {
    Write-Error "Get-MgRiskDetection was not found. Install the module with: Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser"
    exit 1
}

# --- Connect ----------------------------------------------------------------
try {
    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Write-Line "Connecting to Microsoft Graph (app-only certificate auth)..." 'Cyan'
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Line "Connecting to Microsoft Graph (interactive device code)..." 'Cyan'
        Connect-MgGraph -Scopes $RequiredScope -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

$context = $null
try { $context = Get-MgContext -ErrorAction Stop } catch { $context = $null }
if ($null -eq $context) {
    Write-Error "No Microsoft Graph context after connect. Aborting."
    exit 1
}

# --- Query ------------------------------------------------------------------
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$Days)
$cutoffIso = $cutoff.ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-Line ""
Write-Line "Querying risk detections since $cutoffIso (UTC), last $Days day(s)..." 'Cyan'

$detections = $null
try {
    # Server-side date filter first (fast, but $filter support can vary by tenant).
    $detections = Get-MgRiskDetection -All -Filter "detectedDateTime ge $cutoffIso" -ErrorAction Stop
}
catch {
    Write-Warning "Server-side date filter failed; retrying with a full pull and client-side filtering."
    Write-Warning "Reason: $($_.Exception.Message)"
    try {
        $detections = Get-MgRiskDetection -All -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to query risk detections from Microsoft Graph: $($_.Exception.Message)"
        $script:hadError = $true
    }
}

# Fail loud: if the query itself failed, never print a clean report.
if ($script:hadError) {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Error "Risk detection query did not complete successfully. No report produced."
    exit 1
}

if ($null -eq $detections) { $detections = @() }

# --- Classify (client-side) -------------------------------------------------
$findings = New-Object System.Collections.Generic.List[object]

foreach ($d in $detections) {
    if ($null -eq $d) { continue }

    # Enforce the lookback window client-side too (covers the fallback path).
    $detected = $null
    if ($d.DetectedDateTime) { $detected = ([datetime]$d.DetectedDateTime).ToUniversalTime() }
    if ($detected -and $detected -lt $cutoff) { continue }

    $state = ("$($d.RiskState)").Trim().ToLower()
    if ($ClosedStates -notcontains $state) { continue }

    $level = ("$($d.RiskLevel)").Trim().ToLower()
    $reviewPriority = switch ($level) {
        'high'   { 'HIGH' }
        'medium' { 'MEDIUM' }
        default  { 'LOW' }
    }

    $findings.Add([pscustomobject]@{
        UserPrincipalName = $d.UserPrincipalName
        UserDisplayName   = $d.UserDisplayName
        RiskEventType     = $d.RiskEventType
        OriginalRiskLevel = $d.RiskLevel
        RiskState         = $d.RiskState
        RiskDetail        = $d.RiskDetail
        ClosedBy          = Get-RiskDetailLabel -Detail ("$($d.RiskDetail)")
        DetectedDateTime  = $d.DetectedDateTime
        LastUpdatedUtc    = $d.LastUpdatedDateTime
        IpAddress         = $d.IpAddress
        Location          = Format-Location -Location $d.Location
        DetectionId       = $d.Id
        ReviewPriority    = $reviewPriority
    }) | Out-Null
}

# --- Report -----------------------------------------------------------------
$now = (Get-Date).ToString('dd MMM yyyy HH:mm')
$bar = ('=' * 64)

Write-Line ""
Write-Line $bar 'DarkCyan'
Write-Line "  DISMISSED / AUTO-REMEDIATED RISK DETECTION AUDIT - $now" 'White'
Write-Line $bar 'DarkCyan'
Write-Line ("  Tenant                 : {0}" -f $context.TenantId)
Write-Line ("  Lookback window        : {0} day(s) (since {1} UTC)" -f $Days, $cutoffIso)
Write-Line ("  Detections examined    : {0}" -f @($detections).Count)
Write-Line ("  Closed detections found: {0}" -f $findings.Count)
Write-Line $bar 'DarkCyan'

if ($findings.Count -eq 0) {
    Write-Line "  No dismissed or auto-remediated risk detections in this window." 'Green'
    Write-Line $bar 'DarkCyan'
}
else {
    $high   = @($findings | Where-Object { $_.ReviewPriority -eq 'HIGH' })
    $medium = @($findings | Where-Object { $_.ReviewPriority -eq 'MEDIUM' })
    $low    = @($findings | Where-Object { $_.ReviewPriority -eq 'LOW' })

    foreach ($f in ($findings | Sort-Object @{Expression = { switch ($_.ReviewPriority) { 'HIGH' {0} 'MEDIUM' {1} default {2} } } }, DetectedDateTime)) {
        $colour = switch ($f.ReviewPriority) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }
        Write-Line ""
        Write-Line ("  [{0}] {1}" -f $f.ReviewPriority, $f.UserPrincipalName) $colour
        Write-Line ("      Detection        : {0}" -f $f.RiskEventType)
        Write-Line ("      Original level   : {0}" -f $f.OriginalRiskLevel)
        Write-Line ("      Closed state     : {0}" -f $f.RiskState)
        Write-Line ("      How it was closed: {0} ({1})" -f $f.ClosedBy, $f.RiskDetail)
        Write-Line ("      Detected (UTC)   : {0}" -f $f.DetectedDateTime)
        Write-Line ("      IP / location    : {0} {1}" -f $f.IpAddress, $f.Location)
        Write-Line ("      Detection ID     : {0}" -f $f.DetectionId)
    }

    Write-Line ""
    Write-Line $bar 'DarkCyan'
    Write-Line ("  HIGH priority (original level high)   : {0}" -f $high.Count)   'Red'
    Write-Line ("  MEDIUM priority (original level medium): {0}" -f $medium.Count) 'Yellow'
    Write-Line ("  LOW / other                            : {0}" -f $low.Count)
    Write-Line $bar 'DarkCyan'
    Write-Line "  These detections were closed and no longer appear on the risky-users report." 'Yellow'
    Write-Line "  Re-review the HIGH and MEDIUM entries in ID Protection before trusting the dashboard." 'Yellow'
    Write-Line $bar 'DarkCyan'
}

# --- CSV --------------------------------------------------------------------
if ($ExportCsv) {
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath "DismissedRiskDetectionAudit-$stamp.csv"
    }
    try {
        $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Line ("  CSV written to: {0}" -f $CsvPath) 'Cyan'
    }
    catch {
        Write-Error "Failed to write CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

# --- Disconnect and exit ----------------------------------------------------
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

if ($script:hadError) { exit 1 }
elseif ($findings.Count -gt 0) { exit 2 }
else { exit 0 }
