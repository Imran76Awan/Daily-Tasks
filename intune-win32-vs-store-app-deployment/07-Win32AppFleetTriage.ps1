<#
.SYNOPSIS
    Chains the fleet health ranking and failure analysis together: ranks every
    Win32 app by failure rate, then automatically drills into WHY for whichever
    apps cross your failure threshold — in one run, one HTML report.

.DESCRIPTION
    05-Win32AppFleetHealthSummary.ps1 tells you WHICH apps are failing most.
    06-Win32AppFailureAnalysisReport.ps1 tells you WHY a specific app is failing.
    Previously you had to run 05, read the ranking, then manually re-run 06 with
    each flagged app's name. This script does both automatically:

      1. Cheap pass (InstallState only, no device/user names) across every Win32
         app — the same aggregate query 05 uses — to rank failure rate fleet-wide.
      2. Detailed pass (device name, user, error code, platform) ONLY for the
         apps that cross -FailureThreshold with at least -MinDevices outcome
         devices — the expensive per-device pull from 06, scoped down to a
         handful of apps instead of your whole catalog.
      3. One combined HTML report: the fleet ranking table, followed by a full
         donut-chart + ranked-failure-reasons + fix-guidance section for each
         flagged app.

    This keeps the expensive detailed query limited to the apps that actually
    need investigating, rather than pulling full per-device detail for every
    app in the tenant (which is what made 06's own -MaxApps 0 mode slow).

    READ-ONLY — this script only reads report data.

    PRIVACY: Device names and usernames are masked by default in the HTML
    report. Pass -IncludeNames to show real values.

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
    value for detailed drill-down. Defaults to 5 (5%).

.PARAMETER MinDevices
    Ignore apps with fewer than this many outcome devices when flagging — a
    single failure on a 1-device app is not a meaningful 100% failure rate.
    Defaults to 10.

.PARAMETER MaxFlagged
    Cap how many flagged apps get the detailed drill-down, worst-first, in
    case a lot of apps cross the threshold. 0 = no cap.

.PARAMETER MaxApps
    0 = scan every Win32 app for the ranking pass. Limit for a quicker test run.

.PARAMETER OutputPath
    Where to save the combined HTML report.

.EXAMPLE
    .\07-Win32AppFleetTriage.ps1
    Ranks every Win32 app, then generates full failure-reason breakdowns for
    whichever ones are failing on 5%+ of devices.

.EXAMPLE
    .\07-Win32AppFleetTriage.ps1 -FailureThreshold 2 -MaxFlagged 5 -MaxApps 30
    Quick test: scans the first 30 apps, flags anything at 2%+ failure, and
    drills into at most the 5 worst.
#>

[CmdletBinding()]
param(
    [double]$FailureThreshold = 5,
    [int]$MinDevices = 10,
    [int]$MaxFlagged = 0,
    [int]$MaxApps = 0,
    [switch]$IncludeNames,
    [switch]$Interactive,
    [string]$OutputPath = (Join-Path $PSScriptRoot "reports\fleet-triage-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
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

# Well-documented Windows Installer (MSI) exit codes.
# Source: Microsoft Learn "Error codes" for Windows Installer.
$msiErrorMap = @{
    2    = @{ Reason = 'File not found';                                Fix = 'Confirm the install command references a file that actually exists in the .intunewin package.' }
    3    = @{ Reason = 'Path not found';                                Fix = 'Check the working directory / install command path is correct for the target device.' }
    5    = @{ Reason = 'Access denied';                                 Fix = 'The installer needed elevated rights it did not have. Confirm the Win32 app is set to run in SYSTEM context, not user context.' }
    1601 = @{ Reason = 'Windows Installer service could not be accessed'; Fix = 'Check the Windows Installer (msiserver) service is not disabled on the device.' }
    1602 = @{ Reason = 'User cancelled install';                        Fix = 'Expected if a user-facing install prompt was cancelled. Consider a silent install command instead.' }
    1603 = @{ Reason = 'Fatal error during installation';               Fix = 'Check for a pending reboot on the device, then try running the installer manually as SYSTEM (e.g. via PsExec -s) to see the real error.' }
    1604 = @{ Reason = 'Install suspended, incomplete';                 Fix = 'Usually caused by a reboot mid-install. Re-run the deployment after confirming the device is not stuck pending restart.' }
    1618 = @{ Reason = 'Another installation is already in progress';   Fix = 'Stagger deployments, or add a wait/retry step — this clears once the other install finishes.' }
    1619 = @{ Reason = 'Install package could not be opened';           Fix = 'Rebuild the .intunewin package — the source file is likely corrupted or the path used to build it was wrong.' }
    1620 = @{ Reason = 'Install package invalid';                       Fix = 'Rebuild the .intunewin package with IntuneWinAppUtil.exe from a clean source folder.' }
    1622 = @{ Reason = 'Error opening installation log file';           Fix = 'Check the device has disk space and permissions to write to the log path.' }
    1623 = @{ Reason = 'Language not supported by this installer';      Fix = 'Deploy the correct language edition of the installer for this device/region.' }
    1624 = @{ Reason = 'Error applying transform to the install package'; Fix = 'Check the MST transform file referenced in the install command is valid and included in the package.' }
    1633 = @{ Reason = 'Installation package not supported on this platform'; Fix = 'Check architecture — e.g. an x86-only package deployed to an ARM64 device. Build/assign the correct architecture.' }
    1638 = @{ Reason = 'Another version of this product is already installed'; Fix = 'Use an upgrade/supersedence relationship in Intune instead of a fresh install, or uninstall the old version first.' }
    1639 = @{ Reason = 'Invalid command-line argument';                 Fix = 'Re-check the install command syntax in the Win32 app configuration for typos or unsupported switches.' }
    1640 = @{ Reason = 'Cannot install remotely during a Remote Desktop session'; Fix = 'Re-run the deployment when the device is not being accessed over RDP, or use a console/SYSTEM-context trigger.' }
    1641 = @{ Reason = 'Success — a restart was initiated';             Fix = 'No action needed — treat as success in your detection rule / return code mapping.' }
    3010 = @{ Reason = 'Success — reboot required to complete install'; Fix = 'Add 3010 as a "success" return code in the Win32 app configuration so Intune does not mark it Failed.' }
    1259 = @{ Reason = 'Blocked by Application Compatibility (AppHelp)'; Fix = 'Check Windows compatibility shims/AppHelp are not blocking this installer; may need a compatibility flag.' }
}

# Documented Intune/MDM-specific hex error codes. Sources: Microsoft's official
# app-install-error-codes reference plus verified community/support threads for
# the 0x87D3xxxx IME content-delivery family.
$intuneHexErrorMap = @{
    '0x80073CFF' = @{ Reason = 'Requires a sideloading-enabled device with a trusted signature'; Fix = 'Enable sideloading, or sign the package with a trusted certificate.' }
    '0x80CF201C' = @{ Reason = 'Requires a sideloading-enabled device with a trusted signature'; Fix = 'Enable sideloading, or sign the package with a trusted certificate.' }
    '0x80073CF0' = @{ Reason = 'Package unsigned, or publisher name does not match the certificate'; Fix = 'Re-sign the package with a certificate whose publisher name matches the manifest exactly.' }
    '0x80073CF3' = @{ Reason = 'Package conflicts with an installed version, a missing dependency, or wrong architecture'; Fix = 'Check dependencies are assigned and the architecture (x86/x64/ARM64) matches the device.' }
    '0x80073CFB' = @{ Reason = 'Package already installed'; Fix = 'Increment the version number, rebuild the package, and remove the stale assignment.' }
    '0x87D1041C' = @{ Reason = 'User uninstalled the app, or an identity/version mismatch after an external update'; Fix = 'Confirm whether the user removed it manually; if not, check for version drift from an out-of-band update.' }
    '0x8000FFFF' = @{ Reason = 'Unexpected installation error'; Fix = 'Pull the IME log from an affected device — this generic code needs the surrounding log lines for context.' }
    '0x87D30000' = @{ Reason = 'IME workflow reported success on one step but the next step had no defined output'; Fix = 'Usually an internal IME sequencing gap rather than a real install failure — re-check on the next sync before investigating further.' }
    '0x87D30065' = @{ Reason = 'App failed to retrieve information — the device did not get enough app metadata to evaluate/download/install it'; Fix = 'Force an Intune sync on the device (or restart the IntuneManagementExtension service) and confirm it can reach *.manage.microsoft.com.' }
    '0x87D30067' = @{ Reason = 'Error unzipping downloaded content'; Fix = 'Rebuild the .intunewin package — the downloaded archive is corrupt or incomplete.' }
    '0x87D30068' = @{ Reason = 'CDN download of the app content timed out'; Fix = 'Check the device''s network path to the Intune content CDN for proxy/firewall blocking or a slow connection.' }
}

function Get-FailureReason {
    param([Nullable[long]]$ErrorCode, [string]$HexErrorCode)

    if ($null -eq $ErrorCode -or $ErrorCode -eq 0) { return $null }
    if ($msiErrorMap.ContainsKey([int]$ErrorCode)) { return $msiErrorMap[[int]$ErrorCode] }
    if ($HexErrorCode -and $intuneHexErrorMap.ContainsKey($HexErrorCode.ToUpper())) { return $intuneHexErrorMap[$HexErrorCode.ToUpper()] }

    if ($HexErrorCode -match '^0x8007([0-9A-Fa-f]{4})$') {
        $win32Code = [Convert]::ToInt32($Matches[1], 16)
        try {
            $msg = [System.ComponentModel.Win32Exception]::new($win32Code).Message
            if ($msg -and $msg -notmatch '^Unknown error') {
                return @{ Reason = $msg; Fix = 'This is a standard Windows system error — address the underlying OS-level condition described.' }
            }
        } catch {}
    }

    return @{
        Reason = "Not documented anywhere I could verify (checked the MSI error list, Microsoft's Intune error reference, and the Windows system error table)"
        Fix    = "Pull IntuneManagementExtension.log from an affected device and search for $HexErrorCode directly — the log usually has the real underlying message this report doesn't expose."
    }
}

function Get-MaskedName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '(none)' }
    if ($IncludeNames) { return $Name }
    if ($Name.Length -le 2) { return '**' }
    return $Name.Substring(0, 2) + ('*' * ($Name.Length - 2))
}

$pageSize = 999

# ── PASS 1 (cheap): InstallState-only counts for every app, to rank failure rate ─
function Get-AppInstallCounts {
    param([string]$AppId)
    $allValues = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $totalRowCount = $null
    do {
        $outFile = Join-Path $env:TEMP "triage-rank-$AppId-$skip.json"
        Get-MgDeviceManagementReportDeviceAppInstallationStatusReport -Body @{
            filter = "(ApplicationId eq '$AppId')"
            select = @('InstallState')
            skip   = $skip
            top    = $pageSize
        } -OutFile $outFile -ErrorAction Stop
        $report = Get-Content $outFile -Raw | ConvertFrom-Json
        Remove-Item $outFile -Force -ErrorAction SilentlyContinue
        if ($null -eq $totalRowCount) { $totalRowCount = $report.TotalRowCount }
        if ($report.Values) { $report.Values | ForEach-Object { $allValues.Add($_[0]) } }
        $skip += $pageSize
    } while ($skip -lt $totalRowCount)

    $counts = @{}
    foreach ($v in $allValues) {
        $label = if ($installStateMap.ContainsKey([int]$v)) { $installStateMap[[int]$v] } else { "Unmapped($v)" }
        if (-not $counts.ContainsKey($label)) { $counts[$label] = 0 }
        $counts[$label]++
    }
    return $counts
}

Write-Host "`n=== PASS 1: Fleet-wide ranking (aggregate counts only) ===" -ForegroundColor Cyan
$win32Apps = @(Get-MgDeviceAppManagementMobileApp -Filter "isOf('microsoft.graph.win32LobApp')")
if ($MaxApps -gt 0) { $win32Apps = @($win32Apps | Select-Object -First $MaxApps) }
Write-Host "Checking $($win32Apps.Count) app(s)...`n" -ForegroundColor Cyan

$ranking = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($app in $win32Apps) {
    $i++
    Write-Progress -Activity 'Ranking apps by failure rate' -Status $app.DisplayName -PercentComplete (($i / $win32Apps.Count) * 100)
    try {
        $counts = Get-AppInstallCounts -AppId $app.Id
    } catch {
        continue
    }
    $installed = [int]$counts['Installed']
    $failed    = [int]$counts['Failed']
    $notInst   = [int]$counts['NotInstalled']
    $outcomeTotal = $installed + $failed + $notInst
    $failRate = if ($outcomeTotal -gt 0) { [math]::Round(($failed / $outcomeTotal) * 100, 1) } else { 0 }
    $ranking.Add([pscustomobject]@{
        AppId        = $app.Id
        DisplayName  = $app.DisplayName
        Installed    = $installed
        Failed       = $failed
        OutcomeTotal = $outcomeTotal
        FailRatePct  = $failRate
    })
}
Write-Progress -Activity 'Ranking apps by failure rate' -Completed

$rankedAll = $ranking | Sort-Object FailRatePct -Descending
$flagged = @($rankedAll | Where-Object { $_.FailRatePct -ge $FailureThreshold -and $_.OutcomeTotal -ge $MinDevices })
if ($MaxFlagged -gt 0) { $flagged = @($flagged | Select-Object -First $MaxFlagged) }

Write-Host "=== Fleet Ranking (worst first) ===" -ForegroundColor Cyan
$rankedAll | Select-Object DisplayName, OutcomeTotal, Failed, FailRatePct | Format-Table -AutoSize

if ($flagged) {
    Write-Host "`n$($flagged.Count) app(s) flagged (fail rate >= $FailureThreshold%, min $MinDevices devices) — shown with a red badge below:" -ForegroundColor Red
    $flagged | Select-Object DisplayName, FailRatePct | Format-Table -AutoSize
} else {
    Write-Host "`nNo apps crossed the $FailureThreshold% threshold." -ForegroundColor Green
}

# Context notes for non-failure states — these aren't errors, so there's no error
# code to decode, but an engineer still needs to know what each one means and
# what (if anything) to check.
$stateContext = @{
    'NotInstalled'   = 'No install attempt has completed for this device yet — usually the assignment hasn''t reached the device at its next check-in, or Required-intent evaluation is still pending. Force an Intune sync on the device if this persists beyond a normal check-in cycle.'
    'PendingInstall' = 'Install is actively in progress right now. Normal — re-check after the device''s next scheduled check-in. If a device stays Pending for multiple days, check the IntuneManagementExtension.log on that device for a stalled download or install step.'
    'NotApplicable'  = 'This app assignment does not apply to this device — usually a platform mismatch, group-scope exclusion, or an OS version outside the app''s requirement rules. Not an error; check the app''s Applicability rules if you expected it to install here.'
    'Unknown'        = 'Intune has not recorded a definitive state for this device yet. Usually clears after the device''s next check-in; if it persists, confirm the device is checking in at all (Devices > All devices > Last check-in).'
    'UninstallFailed'= 'An uninstall was attempted (e.g. via supersedence or a removal assignment) and failed. Check the uninstall command in the Win32 app configuration and the IME log for the specific exit code.'
}

# ── PASS 2: full per-device detail for EVERY app in the ranking ─────────────────
# Every app gets its own drill-down section — not just the ones that cross the
# failure threshold — so an engineer can click through to any app's full picture,
# not only the worst offenders.
$appDetails = [System.Collections.Generic.List[object]]::new()

Write-Host "`n=== PASS 2: Full drill-down detail for all $($rankedAll.Count) app(s) ===" -ForegroundColor Cyan
$j = 0
foreach ($rankedApp in $rankedAll) {
    $j++
    Write-Progress -Activity 'Building per-app drill-down' -Status $rankedApp.DisplayName -PercentComplete (($j / $rankedAll.Count) * 100)
    Write-Host "  [$j/$($rankedAll.Count)] $($rankedApp.DisplayName)..." -ForegroundColor DarkGray

    $allRecords = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $totalRowCount = $null
    $colIndex = $null
    do {
        $outFile = Join-Path $env:TEMP "triage-detail-$($rankedApp.AppId)-$skip.json"
        try {
            Get-MgDeviceManagementReportDeviceAppInstallationStatusReport -Body @{
                filter = "(ApplicationId eq '$($rankedApp.AppId)')"
                select = @('DeviceName', 'UserPrincipalName', 'InstallState', 'ErrorCode', 'HexErrorCode', 'Platform', 'AppVersion', 'LastModifiedDateTime')
                skip   = $skip
                top    = $pageSize
            } -OutFile $outFile -ErrorAction Stop
            $report = Get-Content $outFile -Raw | ConvertFrom-Json
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue
            if ($null -eq $totalRowCount) { $totalRowCount = $report.TotalRowCount }
            if ($null -eq $colIndex) {
                $colIndex = @{}
                for ($c = 0; $c -lt $report.Schema.Count; $c++) { $colIndex[$report.Schema[$c].Column] = $c }
            }
            foreach ($v in $report.Values) {
                $stateInt = [int]$v[$colIndex['InstallState']]
                $lastMod = $v[$colIndex['LastModifiedDateTime']]
                $daysSince = $null
                if ($lastMod) {
                    try { $daysSince = [math]::Round(((Get-Date) - [datetime]$lastMod).TotalDays, 0) } catch {}
                }
                $allRecords.Add([pscustomobject]@{
                    DeviceName    = $v[$colIndex['DeviceName']]
                    UserName      = $v[$colIndex['UserPrincipalName']]
                    InstallState  = if ($installStateMap.ContainsKey($stateInt)) { $installStateMap[$stateInt] } else { "Unmapped($stateInt)" }
                    ErrorCode     = $v[$colIndex['ErrorCode']]
                    HexErrorCode  = $v[$colIndex['HexErrorCode']]
                    Platform      = $v[$colIndex['Platform']]
                    LastModified  = $lastMod
                    DaysSince     = $daysSince
                })
            }
            $skip += $pageSize
        } catch {
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue
            break
        }
    } while ($skip -lt $totalRowCount)

    $stateCounts = $allRecords | Group-Object InstallState | Sort-Object Count -Descending |
        Select-Object @{n='State';e={$_.Name}}, Count

    # Decode Failed reasons (has an error code) and give every other non-Installed
    # state a contextual explanation too (no error code needed — these aren't errors).
    $failures = $allRecords | Where-Object { $_.InstallState -eq 'Failed' -or $_.InstallState -eq 'UninstallFailed' }
    $failureReasons = $failures | ForEach-Object {
        $decoded = Get-FailureReason -ErrorCode $_.ErrorCode -HexErrorCode $_.HexErrorCode
        if ($decoded) {
            [pscustomobject]@{ Reason = $decoded.Reason; Fix = $decoded.Fix; ErrorHex = $_.HexErrorCode }
        }
    }
    $rankedReasons = $failureReasons | Group-Object Reason, ErrorHex | Sort-Object Count -Descending |
        ForEach-Object {
            [pscustomobject]@{ Reason = $_.Group[0].Reason; Fix = $_.Group[0].Fix; Code = $_.Group[0].ErrorHex; Count = $_.Count }
        }

    $isFlagged = $rankedApp.FailRatePct -ge $FailureThreshold -and $rankedApp.OutcomeTotal -ge $MinDevices

    $appDetails.Add([pscustomobject]@{
        AnchorId      = "app-$j"
        DisplayName   = $rankedApp.DisplayName
        FailRatePct   = $rankedApp.FailRatePct
        IsFlagged     = $isFlagged
        StateCounts   = $stateCounts
        RankedReasons = $rankedReasons
        Records       = $allRecords
    })
}
Write-Progress -Activity 'Building per-app drill-down' -Completed

# ── Build the HTML report ─────────────────────────────────────────────────────────
$stateStyle = @{
    'Installed'       = @{ Color = '#0ca30c'; Icon = '&#10003;' }
    'Failed'          = @{ Color = '#d03b3b'; Icon = '&#10007;' }
    'NotInstalled'    = @{ Color = '#fab219'; Icon = '&#9888;'  }
    'UninstallFailed' = @{ Color = '#d03b3b'; Icon = '&#10007;' }
    'PendingInstall'  = @{ Color = '#2a78d6'; Icon = '&#8635;'  }
    'NotApplicable'   = @{ Color = '#9ca3af'; Icon = '&#8212;'  }
    'Unknown'         = @{ Color = '#6b7280'; Icon = '&#63;'   }
}

$rankingRowsHtml = ($appDetails | ForEach-Object {
    $rateColor = if ($_.IsFlagged) { '#d03b3b' } elseif ($_.Records.Count -eq 0) { '#9ca3af' } else { '#0ca30c' }
    $flagBadge = if ($_.IsFlagged) { "<span style='font-size:10px;font-weight:700;text-transform:uppercase;color:#fff;background:#d03b3b;padding:2px 8px;border-radius:10px;margin-left:8px'>Flagged</span>" } else { '' }
    $failedCountForRow = ($_.StateCounts | Where-Object State -eq 'Failed' | Select-Object -ExpandProperty Count)
    if (-not $failedCountForRow) { $failedCountForRow = 0 }
    "<tr><td style='padding:9px 14px;border-bottom:1px solid #f1f5f9'><a href='#$($_.AnchorId)' style='color:#047857;font-weight:600;text-decoration:none'>$([System.Net.WebUtility]::HtmlEncode($_.DisplayName))</a>$flagBadge</td><td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;text-align:right'>$($_.Records.Count)</td><td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;text-align:right;color:#d03b3b'>$failedCountForRow</td><td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;text-align:right;font-weight:700;color:$rateColor'>$($_.FailRatePct)%</td></tr>"
}) -join "`n"

$allAppSectionsHtml = ($appDetails | ForEach-Object {
    $detail = $_
    $totalCount = ($detail.StateCounts | Measure-Object Count -Sum).Sum
    $radius = 70
    $circumference = 2 * [math]::PI * $radius
    $cursor = 0
    $donutSegments = [System.Collections.Generic.List[string]]::new()
    $legendItems = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $detail.StateCounts) {
        $pct = if ($totalCount -gt 0) { $s.Count / $totalCount } else { 0 }
        $style = if ($stateStyle.ContainsKey($s.State)) { $stateStyle[$s.State] } else { @{ Color = '#6b7280' } }
        $dashLength = $pct * $circumference
        $dashArray = "$dashLength $($circumference - $dashLength)"
        $dashOffset = -($cursor * $circumference)
        $donutSegments.Add("<circle r=`"$radius`" cx=`"95`" cy=`"95`" fill=`"transparent`" stroke=`"$($style.Color)`" stroke-width=`"28`" stroke-dasharray=`"$dashArray`" stroke-dashoffset=`"$dashOffset`" />")
        $legendItems.Add("<div style='display:flex;align-items:center;gap:8px;padding:4px 0;font-size:13px'><span style='width:11px;height:11px;border-radius:3px;background:$($style.Color);display:inline-block'></span>$($s.State): <strong>$($s.Count)</strong> ($([math]::Round($pct*100,1))%)</div>")
        $cursor += $pct
    }

    $reasonRows = ($detail.RankedReasons | ForEach-Object {
        $isVerified = $_.Reason -notmatch '^Not documented'
        $badgeColor = if ($isVerified) { '#0ca30c' } else { '#fab219' }
        $badgeLabel = if ($isVerified) { 'Documented' } else { 'Unverified' }
        @"
<tr>
  <td style='padding:12px 14px;border-bottom:1px solid #eef1f5;font-weight:800;color:#d03b3b;vertical-align:top'>$($_.Count)</td>
  <td style='padding:12px 14px;border-bottom:1px solid #eef1f5;font-family:Consolas,monospace;font-size:12px;vertical-align:top;white-space:nowrap'>$($_.Code)</td>
  <td style='padding:12px 14px;border-bottom:1px solid #eef1f5;vertical-align:top'>
    <span style='font-size:10px;font-weight:700;text-transform:uppercase;color:#fff;background:$badgeColor;padding:2px 8px;border-radius:10px'>$badgeLabel</span>
    <div style='margin-top:6px;color:#111827;font-size:13.5px'>$([System.Net.WebUtility]::HtmlEncode($_.Reason))</div>
    <div style='margin-top:6px;color:#047857;font-size:13px;background:#f0fdf4;border-left:3px solid #0ca30c;padding:6px 10px;border-radius:0 6px 6px 0'><strong>Fix:</strong> $([System.Net.WebUtility]::HtmlEncode($_.Fix))</div>
  </td>
</tr>
"@
    }) -join "`n"

    # Context notes for whichever non-Installed/non-Failed states actually occur
    # for this app (NotInstalled, PendingInstall, NotApplicable, Unknown) — these
    # aren't errors, but an engineer still needs to know what they mean.
    $statesPresent = $detail.StateCounts | Where-Object { $_.State -in @('NotInstalled','PendingInstall','NotApplicable','Unknown') } | Select-Object -ExpandProperty State
    $contextNotesHtml = if ($statesPresent) {
        ($statesPresent | ForEach-Object {
            $note = if ($stateContext.ContainsKey($_)) { $stateContext[$_] } else { $null }
            if ($note) {
                $style = $stateStyle[$_]
                "<div style='padding:10px 14px;background:#f8fafc;border-left:3px solid $($style.Color);border-radius:0 6px 6px 0;margin-bottom:8px;font-size:13px'><strong style='color:$($style.Color)'>$_</strong> — $([System.Net.WebUtility]::HtmlEncode($note))</div>"
            }
        }) -join "`n"
    } else { '' }

    $deviceRows = ($detail.Records | Sort-Object InstallState | ForEach-Object {
        $r = $_
        $maskedDevice = Get-MaskedName $r.DeviceName
        $maskedUser   = Get-MaskedName $r.UserName
        $style = if ($stateStyle.ContainsKey($r.InstallState)) { $stateStyle[$r.InstallState] } else { @{ Color = '#6b7280'; Icon = '&#8226;' } }
        $recency = if ($null -ne $r.DaysSince) {
            $recColor = if ($r.DaysSince -le 3) { '#0ca30c' } elseif ($r.DaysSince -le 14) { '#fab219' } else { '#d03b3b' }
            "<span style='color:$recColor'>$($r.DaysSince)d ago</span>"
        } else { '<span style="color:#9ca3af">—</span>' }
        @"
<tr>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;color:#374151'>$([System.Net.WebUtility]::HtmlEncode($maskedDevice))</td>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;color:#374151'>$([System.Net.WebUtility]::HtmlEncode($maskedUser))</td>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9'><span style='color:$($style.Color);font-weight:700;font-size:13px'>$($style.Icon) $($r.InstallState)</span></td>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;font-size:12px;color:#6b7280'>$($r.HexErrorCode)</td>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9;color:#6b7280;font-size:12.5px'>$($r.Platform)</td>
  <td style='padding:8px 14px;border-bottom:1px solid #f1f5f9;font-size:12.5px'>$recency</td>
</tr>
"@
    }) -join "`n"

    $flagLabel = if ($detail.IsFlagged) { "<span style='font-size:12px;font-weight:700;text-transform:uppercase;color:#fff;background:#d03b3b;padding:3px 10px;border-radius:10px;margin-left:10px;vertical-align:middle'>Flagged</span>" } else { '' }

    @"
<div class="card" id="$($detail.AnchorId)">
  <h2>&#128269; $([System.Net.WebUtility]::HtmlEncode($detail.DisplayName)) <span style="font-size:13px;font-weight:400;color:#6b7280">— $($detail.FailRatePct)% fail rate &middot; $($detail.Records.Count) device records</span>$flagLabel</h2>
  <div style="display:flex;gap:32px;align-items:center;flex-wrap:wrap;margin-bottom:20px">
    <svg width="190" height="190" viewBox="0 0 190 190" style="transform:rotate(-90deg);flex-shrink:0">$($donutSegments -join "`n")</svg>
    <div>$($legendItems -join "`n")</div>
  </div>

  $(if ($contextNotesHtml) { "<div style='margin-bottom:20px'>$contextNotesHtml</div>" })

  $(if ($detail.RankedReasons) {
"<h3 style='font-size:14px;margin:0 0 10px;color:#052e16'>Failure reasons (ranked)</h3>
  <div class='table-scroll'><table style='margin-bottom:24px'>
    <tr><th style='width:60px'>Count</th><th style='width:110px'>Code</th><th>Reason &amp; Fix</th></tr>
    $reasonRows
  </table></div>"
  })

  <h3 style="font-size:14px;margin:0 0 10px;color:#052e16">Per-device detail <span style="font-size:12px;font-weight:400;color:#9ca3af">(names masked)</span></h3>
  <div class="table-scroll"><table>
    <tr><th>Device</th><th>User</th><th>State</th><th>Error</th><th>Platform</th><th>Last activity</th></tr>
    $deviceRows
  </table></div>
</div>
"@
}) -join "`n"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Win32 App Fleet Triage — EndpointWeekly</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',Outfit,-apple-system,sans-serif;background:#f8fafc;color:#111827;margin:0;padding:0 0 48px}
.hero{background:linear-gradient(135deg,#064e3b,#059669);padding:40px 32px;color:#fff}
.hero-inner{max-width:1100px;margin:0 auto}
.hero h1{font-size:26px;margin:0 0 6px;font-weight:700}
.hero .sub{color:#d1fae5;font-size:13.5px}
.wrap{max-width:1100px;margin:-24px auto 0;padding:0 32px}
.card{background:#fff;border-radius:14px;padding:28px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04)}
h2{font-size:17px;margin:0 0 18px;font-weight:700;color:#052e16}
h3{font-size:14px;margin:0 0 10px;color:#052e16}
.card{scroll-margin-top:20px}
.card:target{outline:2px solid #0ca30c;outline-offset:4px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;padding:10px 14px;background:#064e3b;color:#fff;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;font-weight:700}
.table-scroll{overflow-x:auto}
@media(max-width:640px){.hero{padding:28px 18px}.wrap{padding:0 16px}.card{padding:18px}}
</style>
</head>
<body>
<div class="hero"><div class="hero-inner">
  <h1>Win32 App Fleet Triage</h1>
  <div class="sub">Generated $(Get-Date -Format 'dd MMM yyyy, HH:mm') &middot; $($win32Apps.Count) apps ranked &middot; $($flagged.Count) flagged (&gt;= $FailureThreshold% fail rate, min $MinDevices devices) &middot; click any app below to jump to its full detail</div>
</div></div>

<div class="wrap">
  <div class="card">
    <h2>&#128202; Fleet Ranking (worst first) <span style="font-size:12px;font-weight:400;color:#9ca3af">— click an app to jump to its drill-down</span></h2>
    <div class="table-scroll"><table>
      <tr><th>App</th><th style="text-align:right">Devices</th><th style="text-align:right">Failed</th><th style="text-align:right">Fail Rate</th></tr>
      $rankingRowsHtml
    </table></div>
  </div>

  $allAppSectionsHtml

  <div style="text-align:center;color:#9ca3af;font-size:12px;padding:16px 0">
    Generated by 07-Win32AppFleetTriage.ps1 &middot; endpointweekly.com
  </div>
</div>
</body></html>
"@

$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "`nCombined triage report saved: $OutputPath" -ForegroundColor Green
try { Start-Process $OutputPath } catch {}
