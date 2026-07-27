<#
.SYNOPSIS
    Ranks every Win32 app in your Intune tenant by install failure rate, and
    tracks day-over-day trend — something the Intune admin center cannot show
    you in one view.

.DESCRIPTION
    The Intune portal's "Device install status" report only shows one app at a
    time. To find your worst-performing app across a catalog of hundreds, you'd
    have to open every single app and note the numbers by hand. This script:

      1. Pulls install-state counts for every Win32 app (reusing the same
         Get-MgDeviceManagementReportDeviceAppInstallationStatusReport report
         as 03-CheckWin32AppStatus.ps1, fully paginated).
      2. Computes a failure rate: Failed / (Failed + Installed + NotInstalled)
         — NotApplicable and PendingInstall are excluded from the denominator
         since they aren't outcomes yet.
      3. Ranks every app worst-to-best by failure rate in one table.
      4. Flags any app above -FailureThreshold percent.
      5. Saves a timestamped CSV snapshot, and if a previous snapshot exists
         in the same output folder, shows the change in failure rate and
         failed-device count since last run — day-over-day trend the portal
         does not track at all.

    READ-ONLY — this script only reads report data. No device/user names are
    ever printed (this report only needs aggregate counts, not per-device rows).

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Requires:    Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement,
                 Microsoft.Graph.Reports PowerShell modules
    Permissions: DeviceManagementApps.Read.All (Application, for app-only auth)
                 or delegated with -Interactive
    Version:     1.0
    Date:        2026-07-27

.PARAMETER FailureThreshold
    Flag any app whose failure rate (as a percentage) is at or above this
    value. Defaults to 5 (5%).

.PARAMETER MaxApps
    0 = check all Win32 apps. Set a number to limit how many apps are checked
    (useful for a quick test — a full tenant can have hundreds of apps).

.PARAMETER OutputFolder
    Where to save the CSV snapshot used for day-over-day trend comparison.
    Defaults to a "reports" subfolder next to this script.

.EXAMPLE
    .\05-Win32AppFleetHealthSummary.ps1
    Checks every Win32 app, flags anything failing on 5%+ of devices, and
    saves a snapshot for next time's trend comparison.

.EXAMPLE
    .\05-Win32AppFleetHealthSummary.ps1 -FailureThreshold 2 -MaxApps 20
    Quick test against the first 20 apps, flagging anything at 2%+ failure.
#>

[CmdletBinding()]
param(
    [double]$FailureThreshold = 5,
    [int]$MinDevices = 10,   # Ignore apps with fewer than this many outcome devices when flagging — a single failure on a 1-device app is not a meaningful 100% failure rate
    [int]$MaxApps = 0,
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'reports'),
    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'

# ── Module version pin (see 03-CheckWin32AppStatus.ps1 for why) ────────────────
$graphModuleVersion = '2.27.0'
Import-Module Microsoft.Graph.Authentication    -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.DeviceManagement  -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Reports           -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue

# ── Auth settings (app-only certificate) ──────────────────────────────────────
$tenantId   = 'YOUR-TENANT-ID'        # e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$clientId   = 'YOUR-APP-CLIENT-ID'    # App registration (client) ID from Entra
$thumbprint = 'YOUR-CERT-THUMBPRINT'  # Certificate thumbprint on the app registration

if ($Interactive) {
    Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome
} else {
    Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -NoWelcome
}

# installState integer -> readable label (per Microsoft's resultantAppState enum:
# https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-resultantappstate)
$installStateMap = @{
    -1 = 'NotApplicable'
    1  = 'Installed'
    2  = 'Failed'
    3  = 'NotInstalled'
    4  = 'UninstallFailed'
    5  = 'PendingInstall'
    99 = 'Unknown'
}

$pageSize = 999

function Get-AppInstallCounts {
    param([string]$AppId)

    $allRows = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $totalRowCount = $null

    do {
        $outFile = Join-Path $env:TEMP "fleet-health-$AppId-$skip.json"
        Get-MgDeviceManagementReportDeviceAppInstallationStatusReport -Body @{
            filter = "(ApplicationId eq '$AppId')"
            select = @('InstallState')
            skip   = $skip
            top    = $pageSize
        } -OutFile $outFile -ErrorAction Stop

        $report = Get-Content $outFile -Raw | ConvertFrom-Json
        Remove-Item $outFile -Force -ErrorAction SilentlyContinue

        if ($null -eq $totalRowCount) { $totalRowCount = $report.TotalRowCount }
        if ($report.Values) { $report.Values | ForEach-Object { $allRows.Add($_[0]) } }

        $skip += $pageSize
    } while ($skip -lt $totalRowCount)

    $counts = @{}
    foreach ($v in $allRows) {
        $label = if ($installStateMap.ContainsKey([int]$v)) { $installStateMap[[int]$v] } else { "Unmapped($v)" }
        if (-not $counts.ContainsKey($label)) { $counts[$label] = 0 }
        $counts[$label]++
    }
    return $counts
}

Write-Host "`n=== Win32 App Fleet Health Summary ===" -ForegroundColor Cyan

$win32Apps = Get-MgDeviceAppManagementMobileApp -Filter "isOf('microsoft.graph.win32LobApp')"
if ($MaxApps -gt 0) { $win32Apps = $win32Apps | Select-Object -First $MaxApps }
Write-Host "Checking $($win32Apps.Count) Win32 app(s)...`n" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($app in $win32Apps) {
    $i++
    Write-Progress -Activity 'Checking Win32 apps' -Status $app.DisplayName -PercentComplete (($i / $win32Apps.Count) * 100)

    try {
        $counts = Get-AppInstallCounts -AppId $app.Id
    } catch {
        Write-Host "  Skipped '$($app.DisplayName)': $($_.Exception.Message)" -ForegroundColor DarkYellow
        continue
    }

    $installed   = [int]$counts['Installed']
    $failed      = [int]$counts['Failed']
    $notInst     = [int]$counts['NotInstalled']
    $pending     = [int]$counts['PendingInstall']
    $notApplic   = [int]$counts['NotApplicable']
    $unknown     = [int]$counts['Unknown']
    $total       = $installed + $failed + $notInst + $pending + $notApplic + $unknown

    # Failure rate denominator excludes NotApplicable/Pending — they aren't outcomes yet
    $outcomeTotal = $installed + $failed + $notInst
    $failRate = if ($outcomeTotal -gt 0) { [math]::Round(($failed / $outcomeTotal) * 100, 1) } else { 0 }

    $results.Add([pscustomobject]@{
        AppId         = $app.Id
        DisplayName   = $app.DisplayName
        TotalDevices  = $total
        Installed     = $installed
        Failed        = $failed
        NotInstalled  = $notInst
        Pending       = $pending
        NotApplicable = $notApplic
        Unknown       = $unknown
        OutcomeTotal  = $outcomeTotal
        FailRatePct   = $failRate
    })
}
Write-Progress -Activity 'Checking Win32 apps' -Completed

# ── Rank worst-to-best by failure rate ──────────────────────────────────────────
$ranked = $results | Sort-Object FailRatePct -Descending

Write-Host "=== Ranked by Failure Rate (worst first) ===" -ForegroundColor Cyan
$ranked | Select-Object DisplayName, TotalDevices, OutcomeTotal, Installed, Failed, FailRatePct |
    Format-Table -AutoSize

# Only flag apps with at least -MinDevices outcome devices — a single failure on a
# 1-device app is a meaningless 100% failure rate, not a real signal.
$flagged = $ranked | Where-Object { $_.FailRatePct -ge $FailureThreshold -and $_.OutcomeTotal -ge $MinDevices }
$smallSample = $ranked | Where-Object { $_.FailRatePct -ge $FailureThreshold -and $_.OutcomeTotal -lt $MinDevices -and $_.OutcomeTotal -gt 0 }

if ($flagged) {
    Write-Host "`n=== FLAGGED: fail rate >= $FailureThreshold% (min $MinDevices devices) ===" -ForegroundColor Red
    $flagged | Select-Object DisplayName, Failed, OutcomeTotal, FailRatePct | Format-Table -AutoSize
} else {
    Write-Host "`nNo apps at or above the $FailureThreshold% failure threshold (with at least $MinDevices devices)." -ForegroundColor Green
}

if ($smallSample) {
    Write-Host "`n=== Small sample, not flagged (fewer than $MinDevices devices) ===" -ForegroundColor DarkYellow
    $smallSample | Select-Object DisplayName, Failed, OutcomeTotal, FailRatePct | Format-Table -AutoSize
}

# ── Save snapshot + compare to previous run ─────────────────────────────────────
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

$previousSnapshot = Get-ChildItem $OutputFolder -Filter 'fleet-health-*.csv' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($previousSnapshot) {
    Write-Host "`n=== Change since last snapshot ($($previousSnapshot.Name)) ===" -ForegroundColor Cyan
    $previous = Import-Csv $previousSnapshot.FullName
    $trend = foreach ($r in $ranked) {
        $prev = $previous | Where-Object { $_.AppId -eq $r.AppId } | Select-Object -First 1
        if ($prev) {
            $failedDelta = $r.Failed - [int]$prev.Failed
            $rateDelta   = [math]::Round($r.FailRatePct - [double]$prev.FailRatePct, 1)
            if ($failedDelta -ne 0 -or $rateDelta -ne 0) {
                [pscustomobject]@{
                    DisplayName   = $r.DisplayName
                    FailedNow     = $r.Failed
                    FailedChange  = $failedDelta
                    FailRateNow   = $r.FailRatePct
                    FailRateChange= $rateDelta
                }
            }
        }
    }
    if ($trend) {
        $trend | Sort-Object FailedChange -Descending | Format-Table -AutoSize
    } else {
        Write-Host "  No change in failure counts for any app since last snapshot." -ForegroundColor DarkGray
    }
} else {
    Write-Host "`nNo previous snapshot found in $OutputFolder — this run becomes the baseline for next time." -ForegroundColor DarkGray
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $OutputFolder "fleet-health-$timestamp.csv"
$ranked | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nSnapshot saved: $csvPath" -ForegroundColor Cyan
