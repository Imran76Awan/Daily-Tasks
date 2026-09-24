<#
.SYNOPSIS
    Reports open Microsoft Defender for Cloud Apps alerts matching either the legacy
    "Activity performed by terminated user" alert or the new "Activity by a deprovisioned
    user (preview)" detection.

.DESCRIPTION
    Microsoft retired the legacy "Activity performed by terminated user" alert in Defender
    for Cloud Apps and replaced it with a Microsoft-maintained dynamic detection called
    "Activity by a deprovisioned user (preview)" (Message Center post MC1402307, rollout
    late June to early July 2026). This script queries the documented Defender for Cloud
    Apps Alerts API "List" endpoint (POST /api/v1/alerts/) for open alerts in a configurable
    lookback window, then filters the results client-side for a title containing either
    "terminated user" or "deprovisioned" (the documented Alerts API filter list has no
    title-text filter, so this match has to happen after the data comes back).

    This script is READ-ONLY. It calls only the documented List alerts request. It never
    calls the Close benign, Close false positive, Close true positive, Mark alert as read,
    or Mark alert as unread endpoints, and it never modifies any alert or policy state.

    Reference: https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts-list
               https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts

.PARAMETER TenantHost
    The Defender for Cloud Apps tenant hostname, in the form used by the classic Cloud App
    Security portal API, e.g. "contoso.us2.portal.cloudappsecurity.com". Find this value in
    the Microsoft Defender portal under Settings > Cloud Apps > API tokens, or from your
    tenant's Cloud Apps portal URL.

.PARAMETER ApiToken
    A Defender for Cloud Apps API token with at least read access to alerts. Generate one in
    the Microsoft Defender portal under Settings > Cloud Apps > API tokens. Pass this as a
    SecureString-backed value where possible; this script accepts a plain string parameter
    for simplicity but does not write the token to disk, a log file, or the console at any
    point.

.PARAMETER LookbackDays
    Number of days back to search for open alerts. Default is 30. Maps to the documented
    "date" filter with the "gte_ndays" operator.

.PARAMETER CsvPath
    Optional path to export matching alerts as CSV, one row per alert. Alert IDs are
    included in the export; redact them before sharing the CSV outside your own team, since
    an alert ID can be used to look up the full alert record in your tenant.

.EXAMPLE
    .\Get-CloudAppsDeprovisionedAlertReport.ps1 -TenantHost "contoso.us2.portal.cloudappsecurity.com" -ApiToken $token

    Reports open alerts from the last 30 days matching either the legacy or new
    terminated/deprovisioned-user alert title.

.EXAMPLE
    .\Get-CloudAppsDeprovisionedAlertReport.ps1 -TenantHost "contoso.us2.portal.cloudappsecurity.com" -ApiToken $token -LookbackDays 90 -CsvPath "C:\Reports\cloudapps-deprovisioned-alerts.csv"

    Extends the lookback window to 90 days and exports matching alerts to CSV.

.NOTES
    Author: Imran Awan (EndpointWeekly)
    Blog post: https://endpointweekly.com/blog/defender-cloud-apps-deprovisioned-user-alert-unified-rbac.html
    Read-only. Requires a Defender for Cloud Apps API token with alert read access.
    Exit codes:
      0 = script ran successfully, no matching alerts found
      1 = script ran successfully, one or more matching alerts found (informational, not an error)
      2 = script failed to run (invalid parameters, API/auth error, or unexpected response shape)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantHost,

    [Parameter(Mandatory = $true)]
    [string]$ApiToken,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$LookbackDays = 30,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$script:hadError = $false

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host $Message
}

if ([string]::IsNullOrWhiteSpace($TenantHost)) {
    Write-Error "TenantHost cannot be empty."
    exit 2
}

if ([string]::IsNullOrWhiteSpace($ApiToken)) {
    Write-Error "ApiToken cannot be empty."
    exit 2
}

$apiUrl = "https://$TenantHost/api/v1/alerts/"

$requestBody = @{
    filters       = @{
        alertOpen = @{ eq = $true }
        date      = @{ gte_ndays = $LookbackDays }
    }
    limit         = 100
    sortField     = "date"
    sortDirection = "desc"
} | ConvertTo-Json -Depth 5

Write-Section "Querying Defender for Cloud Apps Alerts API..."
Write-Host "Endpoint: $apiUrl"
Write-Host "Lookback window: $LookbackDays days | Open alerts only"

$headers = @{
    "Authorization" = "Token $ApiToken"
    "Content-Type"  = "application/json"
}

try {
    $response = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $requestBody -ErrorAction Stop
}
catch {
    Write-Error "Failed to query the Defender for Cloud Apps Alerts API: $($_.Exception.Message)"
    $script:hadError = $true
    exit 2
}

if ($null -eq $response) {
    Write-Error "The API returned an empty response. This does not necessarily mean there are no alerts - verify manually before trusting this result."
    exit 2
}

if (-not ($response.PSObject.Properties.Name -contains "data")) {
    Write-Error "The API response did not include a 'data' property. The response shape may have changed - verify against the current Alerts API documentation before relying on this script."
    exit 2
}

$allAlerts = @($response.data)

$matchingAlerts = $allAlerts | Where-Object {
    $_.title -and (
        $_.title -match "(?i)terminated user" -or
        $_.title -match "(?i)deprovisioned"
    )
}

$legacyCount = @($matchingAlerts | Where-Object { $_.title -match "(?i)terminated user" }).Count
$newCount    = @($matchingAlerts | Where-Object { $_.title -match "(?i)deprovisioned" }).Count

$severityMap = @{ 0 = "Low"; 1 = "Medium"; 2 = "High" }
$resolutionMap = @{ 0 = "Open"; 1 = "Dismissed"; 2 = "Resolved"; 3 = "FalsePositive"; 4 = "Benign"; 5 = "TruePositive" }

Write-Section "Alerts matching legacy or new terminated/deprovisioned-user detection:"

if ($matchingAlerts.Count -eq 0) {
    Write-Host "None found in the last $LookbackDays days."
}
else {
    $rows = foreach ($alert in $matchingAlerts) {
        $severityText   = if ($severityMap.ContainsKey([int]$alert.severityValue)) { $severityMap[[int]$alert.severityValue] } else { "Unknown" }
        $resolutionText = if ($resolutionMap.ContainsKey([int]$alert.resolutionStatusValue)) { $resolutionMap[[int]$alert.resolutionStatusValue] } else { "Unknown" }
        $timestampUtc   = if ($alert.timestamp) { [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$alert.timestamp).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }

        [PSCustomObject]@{
            Title             = $alert.title
            Severity          = $severityText
            ResolutionStatus  = $resolutionText
            TimestampUtc      = $timestampUtc
            AlertId           = $alert._id
        }
    }

    $rows | Format-Table -AutoSize | Out-String | Write-Host

    if ($CsvPath) {
        try {
            $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Exported $($rows.Count) row(s) to $CsvPath"
        }
        catch {
            Write-Error "Failed to export CSV to '$CsvPath': $($_.Exception.Message)"
            $script:hadError = $true
        }
    }
}

Write-Section "Total matching alerts found: $($matchingAlerts.Count)"
Write-Host "Legacy-named alerts found  : $legacyCount"
Write-Host "New-named alerts found     : $newCount"

Write-Host ""
if ($matchingAlerts.Count -eq 0) {
    Write-Host "RESULT: No alerts matching either the legacy or new terminated/deprovisioned-user"
    Write-Host "detection were found in the lookback window. This does not necessarily mean the"
    Write-Host "detection is inactive in your tenant - it may simply mean no matching activity"
    Write-Host "has occurred recently. Re-run periodically, and separately confirm in Policy"
    Write-Host "management whether the new alert is present for your tenant."
}
elseif ($newCount -gt 0 -and $legacyCount -eq 0) {
    Write-Host "RESULT: Your tenant is producing alerts under the NEW alert name."
    Write-Host "This confirms the migration has completed for this tenant and any"
    Write-Host "runbook or SIEM rule still matching only the legacy title will miss"
    Write-Host "these going forward."
}
elseif ($legacyCount -gt 0 -and $newCount -eq 0) {
    Write-Host "RESULT: Your tenant is still producing alerts under the LEGACY alert name."
    Write-Host "The migration to the new dynamic detection model has likely not reached"
    Write-Host "this tenant yet. Keep runbooks matching the legacy name for now, and add"
    Write-Host "the new name too so you are ready when it lands."
}
else {
    Write-Host "RESULT: Both the legacy and new alert names appear in this window."
    Write-Host "This tenant is mid-transition. Keep both strings active in every runbook"
    Write-Host "and SIEM rule until you consistently see only the new name."
}

if ($script:hadError) {
    exit 2
}
elseif ($matchingAlerts.Count -gt 0) {
    exit 1
}
else {
    exit 0
}
