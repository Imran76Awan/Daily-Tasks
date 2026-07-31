<#
.SYNOPSIS
    Report-only audit that flags Microsoft Entra access review definitions which
    silently KEEP access when reviewers do not respond before the deadline.

.DESCRIPTION
    An access review can be configured so that, when the review period ends with no
    reviewer decision, a default ("fallback") decision is applied automatically.
    Two settings on the review definition control this:

        autoApplyDecisionsEnabled  - decisions are applied automatically when the
                                     instance duration ends, whether or not the
                                     reviewers responded.
        defaultDecisionEnabled     - a default decision is used for principals no
                                     reviewer acted on.
        defaultDecision            - the default decision itself. One of
                                     'Approve', 'Deny', or 'Recommendation'.

    The dangerous, silent combination this script hunts for is:

        autoApplyDecisionsEnabled = True  AND
        defaultDecisionEnabled    = True  AND
        defaultDecision           = 'Approve'

    In that state a departed or stale user whose access nobody reviews is
    auto-APPROVED and keeps the role. Admins commonly assume "no response means
    access is removed" - the opposite is true here.

    A second, conditional case is flagged for review:

        defaultDecision = 'Recommendation'

    A recommendation is "Approve" for a user who signed in during the look-back
    window, so an active-but-unreviewed user still keeps access. Only inactive
    users get a deny recommendation. These are reported as MEDIUM risk.

    This script is READ-ONLY. It enumerates access review definitions, inspects
    their settings, reports the risky ones, and exits with a non-zero code if any
    are found. It never creates, modifies, deletes, resets, applies, or stops any
    access review or decision.

    Least-privilege Microsoft Graph scope: AccessReview.Read.All

.PARAMETER TenantId
    Directory (tenant) ID for app-only certificate authentication.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate installed in the local certificate store,
    used for app-only authentication.

.PARAMETER UseDeviceCode
    Interactive fallback. Signs in with the device code flow using the delegated
    AccessReview.Read.All scope instead of app-only certificate auth.

.PARAMETER ExportCsv
    Switch. When present, writes the findings to a CSV file.

.PARAMETER CsvPath
    Optional path for the CSV output. Defaults to a timestamped file in the
    current directory. Implies -ExportCsv.

.EXAMPLE
    .\Get-AccessReviewAutoApproveRisk.ps1 -TenantId <guid> -ClientId <guid> -CertificateThumbprint <thumbprint>

    Runs unattended with app-only certificate auth and reports risky reviews.

.EXAMPLE
    .\Get-AccessReviewAutoApproveRisk.ps1 -UseDeviceCode -ExportCsv

    Signs in interactively via device code and exports findings to a timestamped CSV.

.NOTES
    Author  : Imran Awan - EndpointWeekly
    Module  : Microsoft.Graph.Identity.Governance
    Scope   : AccessReview.Read.All (read-only)
    Exit    : 0 = no risky reviews found
              1 = a script or Graph query error occurred (results NOT trustworthy)
              2 = one or more risky reviews found

    Report-only. This script makes NO changes to any tenant object.
    Multi-stage reviews store some settings per stage (stageSettings). Where a
    definition has stageSettings, this script reports that fact so the review can
    be confirmed in the portal, because per-stage settings can override the
    definition-level settings inspected here.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$ExportCsv,

    [Parameter()]
    [string]$CsvPath
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:hadError = $false
$RequiredScope   = 'AccessReview.Read.All'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host "  $Text"
    Write-Host ('=' * 70)
}

# ---------------------------------------------------------------------------
# Module check
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Identity.Governance')) {
    Write-Error "Required module 'Microsoft.Graph.Identity.Governance' is not installed. Run: Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser"
    exit 1
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph (fail loud)
# ---------------------------------------------------------------------------
try {
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop

    if ($PSCmdlet.ParameterSetName -eq 'DeviceCode') {
        Write-Host "Connecting to Microsoft Graph (device code, scope: $RequiredScope)..."
        Connect-MgGraph -Scopes $RequiredScope -UseDeviceCode -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host 'Connecting to Microsoft Graph (app-only certificate auth)...'
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

$context = Get-MgContext
if (-not $context) {
    Write-Error 'No Microsoft Graph context after connect. Aborting.'
    exit 1
}
Write-Host "Connected. Tenant: $($context.TenantId)"

# ---------------------------------------------------------------------------
# Enumerate all access review definitions (fail loud)
# ---------------------------------------------------------------------------
Write-Host 'Enumerating access review definitions...'
$definitions = $null
try {
    $definitions = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to enumerate access review definitions: $($_.Exception.Message)"
    $script:hadError = $true
}

if ($script:hadError) {
    Write-Error 'One or more Graph queries failed. Results are NOT complete or trustworthy. Exiting with code 1.'
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

if ($null -eq $definitions) {
    $definitions = @()
}
$definitions = @($definitions)
Write-Host ("  Access review definitions found : {0}" -f $definitions.Count)

# ---------------------------------------------------------------------------
# Classify each definition
# ---------------------------------------------------------------------------
$findings = New-Object System.Collections.Generic.List[object]

foreach ($def in $definitions) {
    $settings = $def.Settings

    $autoApply     = $false
    $defDecEnabled = $false
    $defDecision   = ''

    if ($null -ne $settings) {
        if ($null -ne $settings.AutoApplyDecisionsEnabled) { $autoApply     = [bool]$settings.AutoApplyDecisionsEnabled }
        if ($null -ne $settings.DefaultDecisionEnabled)    { $defDecEnabled = [bool]$settings.DefaultDecisionEnabled }
        if ($null -ne $settings.DefaultDecision)           { $defDecision   = [string]$settings.DefaultDecision }
    }

    $hasStageSettings = $false
    if ($null -ne $def.StageSettings -and @($def.StageSettings).Count -gt 0) {
        $hasStageSettings = $true
    }

    # Risk logic. A no-response decision only takes effect when it is both
    # auto-applied AND a default decision is enabled.
    $risk = 'None'
    if ($autoApply -and $defDecEnabled) {
        if ($defDecision -eq 'Approve') {
            $risk = 'High'    # unreviewed users are auto-approved and KEEP access
        }
        elseif ($defDecision -eq 'Recommendation') {
            $risk = 'Medium'  # active unreviewed users still keep access via recommendation
        }
    }

    if ($risk -ne 'None') {
        $findings.Add([pscustomobject]@{
            DisplayName               = $def.DisplayName
            DefinitionId              = $def.Id
            Status                    = $def.Status
            AutoApplyDecisionsEnabled = $autoApply
            DefaultDecisionEnabled    = $defDecEnabled
            DefaultDecision           = $defDecision
            HasStageSettings          = $hasStageSettings
            Risk                      = $risk
        })
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Section ("ACCESS REVIEW AUTO-APPROVE RISK REPORT - {0}" -f (Get-Date -Format 'dd MMM yyyy HH:mm'))
Write-Host ("  Definitions scanned : {0}" -f $definitions.Count)
Write-Host ("  Risky definitions   : {0}" -f $findings.Count)

if ($findings.Count -gt 0) {
    foreach ($f in $findings) {
        Write-Host ''
        Write-Host ("  DisplayName        : {0}" -f $f.DisplayName)
        Write-Host ("  DefinitionId       : {0}" -f $f.DefinitionId)
        Write-Host ("  Status             : {0}" -f $f.Status)
        Write-Host ("  AutoApplyDecisions : {0}" -f $f.AutoApplyDecisionsEnabled)
        Write-Host ("  DefaultDecisionOn  : {0}" -f $f.DefaultDecisionEnabled)
        Write-Host ("  DefaultDecision    : {0}" -f $f.DefaultDecision)
        Write-Host ("  MultiStageSettings : {0}" -f $f.HasStageSettings)
        if ($f.Risk -eq 'High') {
            Write-Host ("  RISK: HIGH - unreviewed users are auto-approved and KEEP access") -ForegroundColor Red
        }
        else {
            Write-Host ("  RISK: MEDIUM - active unreviewed users keep access via recommendation") -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host ''
    Write-Host '  No access review is configured to silently keep access on no-response.'
}
Write-Host ''
Write-Host ('=' * 70)

# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
if ($ExportCsv -or $PSBoundParameters.ContainsKey('CsvPath')) {
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("AccessReviewAutoApproveRisk_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    try {
        if ($findings.Count -gt 0) {
            $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        }
        else {
            # Write an empty, header-only file so evidence exists either way.
            ([pscustomobject]@{
                DisplayName = ''; DefinitionId = ''; Status = ''
                AutoApplyDecisionsEnabled = ''; DefaultDecisionEnabled = ''
                DefaultDecision = ''; HasStageSettings = ''; Risk = ''
            }) | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Clear-Content -Path $CsvPath -ErrorAction SilentlyContinue
            'DisplayName,DefinitionId,Status,AutoApplyDecisionsEnabled,DefaultDecisionEnabled,DefaultDecision,HasStageSettings,Risk' | Set-Content -Path $CsvPath -Encoding UTF8
        }
        Write-Host ("CSV written: {0}" -f $CsvPath)
    }
    catch {
        Write-Error "Failed to write CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

# ---------------------------------------------------------------------------
# Disconnect and exit
# ---------------------------------------------------------------------------
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

if ($script:hadError) {
    Write-Error 'Completed with errors. Exit code 1.'
    exit 1
}
if ($findings.Count -gt 0) {
    exit 2
}
exit 0
