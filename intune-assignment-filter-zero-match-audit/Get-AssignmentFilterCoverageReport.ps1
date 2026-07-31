#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of Microsoft Intune assignment filters. Reports every filter,
    which policies/apps reference it (include or exclude), and flags filters whose
    rule text is empty or matches a known zero-match trap pattern.

.DESCRIPTION
    An "include" assignment filter with a subtly wrong rule can match ZERO devices.
    The Intune portal still shows the assignment as present and raises no error, so a
    compliance or configuration policy can appear "assigned to All Devices" while
    nothing actually lands.

    This script enumerates all assignment filters in the tenant using Microsoft Graph
    (beta), reads each filter's associated assignments from the documented "payloads"
    property, and applies conservative, advisory heuristics to the rule text to
    surface the most common zero-match traps:

      - EMPTY_RULE            The filter has no rule text (High if referenced).
      - OSVERSION_EXACT_MATCH device.osVersion used with an exact-match operator
                              (-eq / -ne / -in / -notIn). Windows reports a full
                              four-part build string (for example 10.0.22631.4317),
                              so an exact match against a partial value such as
                              "10.0.22631" matches nothing. Use -startsWith for
                              partial values, or the version-aware
                              operatingSystemVersion property.
      - ENROLLMENTPROFILE_EXACT_MATCH  device.enrollmentProfileName used with an
                              exact-match operator. Profile names are spelling and
                              spacing sensitive; a renamed or mistyped profile name
                              matches zero devices.
      - UNKNOWN_PROPERTY      The rule references a device.<x> or app.<x> property
                              name that is not in the documented property set
                              (possible typo).
      - UNUSED_FILTER         The filter is not referenced by any assignment
                              (informational only).

    IMPORTANT LIMITATION: Microsoft Graph does NOT expose a documented endpoint that
    returns a count of devices matching a filter rule. The getState function only
    reports whether the filter feature is enabled. The only authoritative way to
    prove a rule matches zero devices is the Intune portal "Preview devices" feature
    when editing a filter, and the filter's "Associated Assignments" tab. This script
    therefore reports RED FLAGS, not proof. Treat every finding as "verify this in
    the portal", not "this is definitely broken".

    This script is REPORT-ONLY. It performs read/list Graph calls only and never
    creates, modifies, deletes, enables, disables, resets, or remediates anything.

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only auth.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the current user or local machine store that is
    registered on the app registration, for app-only auth.

.PARAMETER UseDeviceCode
    Use interactive device-code sign-in instead of app-only certificate auth. The
    signed-in account must hold a role that grants the DeviceManagementConfiguration
    read permission (for example Intune Administrator or a custom read role).

.PARAMETER ExportCsv
    Also write the per-filter results to a CSV file.

.PARAMETER CsvPath
    Path for the CSV file. Defaults to a timestamped file in the current directory.

.EXAMPLE
    .\Get-AssignmentFilterCoverageReport.ps1 -UseDeviceCode

    Interactive read-only run using device-code sign-in.

.EXAMPLE
    .\Get-AssignmentFilterCoverageReport.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumb> -ExportCsv

    Unattended app-only run that also writes a CSV report.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Auth   : App-only certificate OR -UseDeviceCode interactive.
    Scope  : DeviceManagementConfiguration.Read.All (least privilege for listing
             assignment filters).
    Module : Microsoft.Graph.Authentication and Microsoft.Graph.Beta.DeviceManagement.
    Exit   : 0 = clean (no flagged filters), 1 = script/query error,
             2 = flagged filters found.
    This tool is not affiliated with or endorsed by Microsoft.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
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

$ErrorActionPreference = 'Stop'
$script:hadError = $false

# Least-privilege read scope for listing assignment filters.
$requiredScope = 'DeviceManagementConfiguration.Read.All'

# Documented assignment filter property names (device and app), lowercased.
# Source: Microsoft Learn - Assignment filter properties and operators reference.
$knownProperties = @(
    'cpuarchitecture','devicecategory','devicemanagementtype','devicename',
    'deviceownership','devicetrusttype','enrollmentprofilename','isrooted',
    'manufacturer','model','operatingsystemversion','osversion',
    'operatingsystemsku','appversion','devicemanufacturer','devicemodel'
)

function Write-Section {
    param([string]$Text)
    Write-Host ('=' * 64)
    Write-Host "  $Text"
    Write-Host ('=' * 64)
}

function Test-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "[ERROR] Required module '$Name' is not installed." -ForegroundColor Red
        Write-Host "        Install with: Install-Module $Name -Scope CurrentUser" -ForegroundColor Red
        return $false
    }
    return $true
}

# ---------------------------------------------------------------------------
# Preflight: required modules
# ---------------------------------------------------------------------------
$modulesOk = $true
if (-not (Test-Module -Name 'Microsoft.Graph.Authentication')) { $modulesOk = $false }
if (-not (Test-Module -Name 'Microsoft.Graph.Beta.DeviceManagement')) { $modulesOk = $false }
if (-not $modulesOk) {
    Write-Host "[FATAL] Missing prerequisites. Aborting without querying anything." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph (read-only)
# ---------------------------------------------------------------------------
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Beta.DeviceManagement -ErrorAction Stop

    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Write-Host "Connecting to Microsoft Graph (app-only certificate auth)..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host "Connecting to Microsoft Graph (device-code sign-in)..."
        Connect-MgGraph -Scopes $requiredScope -UseDeviceCode -NoWelcome -ErrorAction Stop
    }

    $context = Get-MgContext -ErrorAction Stop
    if ($null -eq $context) {
        throw "No Graph context after connect."
    }
    Write-Host ("Connected. Tenant: {0}" -f $context.TenantId)
}
catch {
    Write-Host "[ERROR] Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[FATAL] Cannot continue without a Graph connection." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Query assignment filters (fail loud on any error)
# ---------------------------------------------------------------------------
$filters = $null
try {
    Write-Host "Enumerating assignment filters (deviceManagement/assignmentFilters)..."
    $filters = Get-MgBetaDeviceManagementAssignmentFilter -All -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Graph query for assignment filters failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:hadError = $true
}

if ($script:hadError) {
    Write-Host "[FATAL] A required query failed. Not reporting results to avoid a false clean report." -ForegroundColor Red
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

if ($null -eq $filters) { $filters = @() }
$filters = @($filters)

# ---------------------------------------------------------------------------
# Analyse each filter
# ---------------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]

foreach ($f in $filters) {

    $rule = [string]$f.Rule
    $findings = New-Object System.Collections.Generic.List[string]

    # Associated assignments come from the documented "payloads" property.
    $payloads = @()
    if ($null -ne $f.Payloads) {
        $payloads = @($f.Payloads)
    }
    elseif ($f.AdditionalProperties -and $f.AdditionalProperties.ContainsKey('payloads')) {
        $payloads = @($f.AdditionalProperties['payloads'])
    }
    $referenced = ($payloads.Count -gt 0)

    # --- Heuristic checks (advisory) ---
    if ([string]::IsNullOrWhiteSpace($rule)) {
        if ($referenced) {
            $findings.Add('EMPTY_RULE (HIGH: referenced by an assignment but has no rule text)')
        }
        else {
            $findings.Add('EMPTY_RULE (INFO: no rule text)')
        }
    }
    else {
        $lc = $rule.ToLowerInvariant()

        # osVersion used with an exact-match operator is the classic zero-match trap.
        if ($lc -match 'osversion\s*-?(eq|ne|in|notin)\b') {
            $findings.Add('OSVERSION_EXACT_MATCH (ADVISORY: exact match on osVersion; use -startsWith for partial build values or operatingSystemVersion)')
        }

        # enrollmentProfileName exact match is spelling/spacing sensitive.
        if ($lc -match 'enrollmentprofilename\s*-?(eq|in|notin)\b') {
            $findings.Add('ENROLLMENTPROFILE_EXACT_MATCH (ADVISORY: exact match on a profile name; verify the exact enrollment profile name)')
        }

        # Property tokens: device.<x> or app.<x>. Flag any not in the documented set.
        $propMatches = [regex]::Matches($lc, '(?:device|app)\.([a-z0-9_]+)')
        $seen = @{}
        foreach ($m in $propMatches) {
            $prop = $m.Groups[1].Value
            if (-not $seen.ContainsKey($prop)) {
                $seen[$prop] = $true
                if ($knownProperties -notcontains $prop) {
                    $findings.Add("UNKNOWN_PROPERTY (ADVISORY: rule references '$prop' which is not a documented filter property; check spelling)")
                }
            }
        }
    }

    if (-not $referenced) {
        $findings.Add('UNUSED_FILTER (INFO: not referenced by any assignment)')
    }

    # A filter is "flagged" if it carries any HIGH or ADVISORY finding.
    $flagged = $false
    foreach ($fi in $findings) {
        if ($fi -match 'HIGH:' -or $fi -match 'ADVISORY:') { $flagged = $true; break }
    }

    $refSummary = ''
    if ($referenced) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($p in $payloads) {
            $ptype = [string]$p.PayloadType
            $pft   = [string]$p.AssignmentFilterType
            $pid   = [string]$p.PayloadId
            $parts.Add(("{0}/{1}/{2}" -f $ptype, $pft, $pid))
        }
        $refSummary = ($parts -join '; ')
    }

    $results.Add([pscustomobject]@{
        DisplayName        = [string]$f.DisplayName
        Platform           = [string]$f.Platform
        ManagementType     = [string]$f.AssignmentFilterManagementType
        FilterId           = [string]$f.Id
        Rule               = $rule
        RuleLength         = $rule.Length
        AssignmentCount    = $payloads.Count
        Referenced         = $referenced
        AssociatedPayloads = $refSummary
        Flagged            = $flagged
        Findings           = ($findings -join ' | ')
    })
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$flaggedList = @($results | Where-Object { $_.Flagged })
$stamp = (Get-Date).ToString('dd MMM yyyy HH:mm')

Write-Host ""
Write-Section "INTUNE ASSIGNMENT FILTER COVERAGE REPORT - $stamp"
Write-Host ("  Assignment filters found : {0}" -f $results.Count)
Write-Host ("  Referenced by assignments: {0}" -f (@($results | Where-Object { $_.Referenced }).Count))
Write-Host ("  Flagged for review       : {0}" -f $flaggedList.Count)
Write-Host ('=' * 64)

foreach ($r in $results) {
    Write-Host ""
    Write-Host ("  Filter        : {0}" -f $r.DisplayName)
    Write-Host ("  Platform      : {0}   ManagementType: {1}" -f $r.Platform, $r.ManagementType)
    Write-Host ("  FilterId      : {0}" -f $r.FilterId)
    Write-Host ("  Rule          : {0}" -f $r.Rule)
    Write-Host ("  Assignments   : {0}" -f $r.AssignmentCount)
    if ($r.Referenced) {
        Write-Host ("  Referenced by : {0}" -f $r.AssociatedPayloads)
    }
    if ($r.Flagged) {
        Write-Host ("  STATUS        : FLAGGED - verify in portal (Preview devices / Associated Assignments)") -ForegroundColor Yellow
        Write-Host ("  Findings      : {0}" -f $r.Findings) -ForegroundColor Yellow
    }
    else {
        Write-Host ("  STATUS        : OK")
        if (-not [string]::IsNullOrWhiteSpace($r.Findings)) {
            Write-Host ("  Notes         : {0}" -f $r.Findings)
        }
    }
}

Write-Host ""
Write-Section "SUMMARY"
Write-Host ("  Total filters  : {0}" -f $results.Count)
Write-Host ("  Flagged        : {0}" -f $flaggedList.Count)
Write-Host ('=' * 64)
Write-Host "  NOTE: Graph cannot count devices that match a filter rule. Findings are"
Write-Host "  RED FLAGS to verify, not proof of zero match. Confirm with the portal"
Write-Host "  'Preview devices' feature when editing the filter."
Write-Host ('=' * 64)

# ---------------------------------------------------------------------------
# Optional CSV export
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("AssignmentFilterCoverage_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    try {
        $results | Select-Object DisplayName,Platform,ManagementType,FilterId,Rule,RuleLength,AssignmentCount,Referenced,AssociatedPayloads,Flagged,Findings |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ("CSV written: {0}" -f $CsvPath)
    }
    catch {
        Write-Host "[ERROR] Failed to write CSV: $($_.Exception.Message)" -ForegroundColor Red
        $script:hadError = $true
    }
}

# ---------------------------------------------------------------------------
# Disconnect and set exit code
# ---------------------------------------------------------------------------
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

if ($script:hadError) {
    exit 1
}
elseif ($flaggedList.Count -gt 0) {
    exit 2
}
else {
    exit 0
}
