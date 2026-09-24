<#
.SYNOPSIS
    Reports Cloud Infrastructure Entitlement Management (CIEM) coverage across
    every Azure subscription visible to the signed-in account.

.DESCRIPTION
    Microsoft Entra Permissions Management (the standalone CIEM product, formerly
    CloudKnox) was fully retired on November 1, 2025, and its collected data
    deleted. Microsoft's native replacement capability, called "Permissions
    Management (CIEM)" in the Azure portal, lives inside the Defender Cloud
    Security Posture Management (CSPM) plan under Microsoft Defender for Cloud.
    It has to be enabled explicitly, per subscription, and only works when the
    Defender CSPM plan itself is on the Standard pricing tier.

    This script is READ-ONLY. For every subscription the signed-in account can
    see, it calls Get-AzSecurityPricing -Name 'CloudPosture' and inspects:
      - The PricingTier property (must be 'Standard' for CIEM to be available
        at all; 'Free' means Defender CSPM itself is not purchased).
      - The Extensions collection for an entry named 'EntraPermissionsManagement'
        with IsEnabled set to 'True'. This exact extension name and its
        availability under the CloudPosture plan is documented in Microsoft's
        own Azure Resource Manager schema reference for Microsoft.Security/pricings.

    It never calls Set-AzSecurityPricing or any other state-changing cmdlet.
    Running this script does not turn CIEM on or off anywhere, and it does not
    modify any Azure resource.

    Scope note: this script audits Azure subscriptions only. It does not audit
    AWS accounts or GCP projects connected to Defender for Cloud - those use
    separate connector resource IDs that are specific to each tenant's
    onboarding and cannot be safely guessed. Check AWS/GCP CIEM coverage
    directly in the Azure portal (Microsoft Defender for Cloud > Environment
    settings) until a connector-aware version of this script exists.

.PARAMETER SubscriptionId
    Optional. One or more specific subscription IDs to check. If omitted, the
    script checks every subscription returned by Get-AzSubscription for the
    signed-in account/context.

.PARAMETER CsvPath
    Optional. Path to a .csv file. If supplied, the per-subscription results
    are also exported there (in addition to the console table), one row per
    subscription. The file is only written after every subscription has been
    checked - a run that errors partway through does not produce a partial
    CSV that could be mistaken for a complete audit.

.EXAMPLE
    .\Get-CiemCoverageReport.ps1

    Checks every subscription visible to the currently signed-in Az context
    and prints a summary table plus a coverage count to the console.

.EXAMPLE
    .\Get-CiemCoverageReport.ps1 -SubscriptionId "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222" -CsvPath "C:\Reports\ciem-coverage.csv"

    Checks only the two named subscriptions and also writes the results to a CSV file.

.NOTES
    Author        : Imran Awan
    Blog post      : https://endpointweekly.com/blog/entra-permissions-management-retirement-ciem-coverage-checklist.html
    Read-only      : Yes - only Get-AzSecurityPricing is called. No Set-* cmdlets are used.
    Requires       : Az.Accounts, Az.Security modules; an authenticated Az session
                     (Connect-AzAccount) with at least Reader access on each
                     subscription checked.
    Exit codes     : 0 = every checked subscription has full CIEM coverage
                     1 = at least one coverage gap was found
                     2 = a script-level error occurred (for example, no Az
                         session, a module missing, or a subscription context
                         switch failing) - this is distinct from "gaps found"
                         and should be treated as a run failure, not a result.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$script:hadError = $false
$ciemExtensionName = 'EntraPermissionsManagement'
$results = New-Object System.Collections.Generic.List[Object]

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}

# --- Confirm required modules are present -----------------------------------
foreach ($moduleName in @('Az.Accounts', 'Az.Security')) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Error "Required module '$moduleName' is not installed. Install it with: Install-Module -Name $moduleName -Scope CurrentUser"
        exit 2
    }
}

# --- Confirm there is an active Az session -----------------------------------
$context = $null
try {
    $context = Get-AzContext -ErrorAction Stop
}
catch {
    Write-Error "Get-AzContext failed: $($_.Exception.Message)"
    exit 2
}

if (-not $context -or -not $context.Account) {
    Write-Error "No active Az session found. Run Connect-AzAccount first, then re-run this script."
    exit 2
}

Write-Host "Signed in as: $($context.Account.Id)" -ForegroundColor DarkGray

# --- Build the list of subscriptions to check --------------------------------
$subscriptions = $null
try {
    if ($SubscriptionId -and $SubscriptionId.Count -gt 0) {
        $subscriptions = foreach ($id in $SubscriptionId) {
            Get-AzSubscription -SubscriptionId $id -ErrorAction Stop
        }
    }
    else {
        $subscriptions = Get-AzSubscription -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to enumerate subscriptions: $($_.Exception.Message)"
    exit 2
}

if (-not $subscriptions -or $subscriptions.Count -eq 0) {
    Write-Error "No subscriptions were found for the signed-in account. Nothing to check."
    exit 2
}

Write-Section "Checking CIEM coverage across $($subscriptions.Count) visible subscription(s)..."

# --- Check each subscription --------------------------------------------------
foreach ($sub in $subscriptions) {
    $subName   = $sub.Name
    $subId     = $sub.Id
    $cspmTier  = 'Unknown'
    $ciemState = 'Unknown'
    $statusText = 'Unknown'

    try {
        Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null

        $cspm = Get-AzSecurityPricing -Name 'CloudPosture' -ErrorAction Stop

        $cspmTier = $cspm.PricingTier

        if ($cspmTier -eq 'Standard') {
            $ciemExtension = $cspm.Extensions |
                Where-Object { $_.Name -eq $ciemExtensionName }

            if ($ciemExtension -and $ciemExtension.IsEnabled -eq 'True') {
                $ciemState  = 'True'
                $statusText = 'OK - full CIEM coverage'
            }
            else {
                $ciemState  = 'False'
                $statusText = 'GAP - Defender CSPM on, CIEM extension off'
            }
        }
        else {
            $ciemState  = 'n/a'
            $statusText = "GAP - Defender CSPM not enabled ($cspmTier tier)"
        }
    }
    catch {
        $script:hadError = $true
        $statusText = "ERROR - $($_.Exception.Message)"
        Write-Warning "Failed to check subscription '$subName' ($subId): $($_.Exception.Message)"
    }

    $results.Add([PSCustomObject]@{
        SubscriptionName = $subName
        SubscriptionId   = $subId
        CspmTier         = $cspmTier
        CiemEnabled      = $ciemState
        Status           = $statusText
    })
}

# --- Report ---------------------------------------------------------------
Write-Host ""
$results | Format-Table -Property SubscriptionName, CspmTier, CiemEnabled, Status -AutoSize

$gapCount   = ($results | Where-Object { $_.Status -like 'GAP*' }).Count
$errorCount = ($results | Where-Object { $_.Status -like 'ERROR*' }).Count
$okCount    = ($results | Where-Object { $_.Status -like 'OK*' }).Count

Write-Host ""
Write-Host "SUMMARY: $okCount of $($results.Count) subscription(s) have full CIEM coverage." -ForegroundColor $(if ($gapCount -eq 0 -and $errorCount -eq 0) { 'Green' } else { 'Yellow' })

if ($gapCount -gt 0) {
    Write-Host "$gapCount subscription(s) have a coverage gap - see Status column above." -ForegroundColor Yellow
}
if ($errorCount -gt 0) {
    Write-Host "$errorCount subscription(s) could not be checked due to an error - see warnings above." -ForegroundColor Red
}

# --- Optional CSV export - only written on a fully-collected result set -----
if ($CsvPath) {
    try {
        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Force -ErrorAction Stop
        Write-Host ""
        Write-Host "Results exported to: $CsvPath" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to export CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

# --- Exit code ---------------------------------------------------------------
if ($script:hadError -or $errorCount -gt 0) {
    exit 2
}
elseif ($gapCount -gt 0) {
    exit 1
}
else {
    exit 0
}
