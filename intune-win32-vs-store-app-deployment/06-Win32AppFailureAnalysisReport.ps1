<#
.SYNOPSIS
    Generates a self-contained HTML report analysing Win32 app install failures
    across your Intune tenant: a pie chart of install states, a ranked "top
    failure reasons" breakdown, and a per-device detail table.

.DESCRIPTION
    The Intune portal shows you a per-app install status count. It does not:
      - Decode WHY installs failed (it shows a raw error code at best, per
        device, one at a time — never ranked across your fleet)
      - Show you a visual breakdown (pie chart) of install state distribution
      - Rank failure reasons so you can see your #1 recurring problem first
      - Let you export a single report covering device name, username,
        platform, app version and decoded failure reason together

    This script pulls per-device install records (DeviceName, UserPrincipalName,
    InstallState, ErrorCode, HexErrorCode, Platform, AppVersion) via
    Get-MgDeviceManagementReportDeviceAppInstallationStatusReport, decodes each
    failure's error code using:
      1. A table of well-documented Windows Installer (MSI) exit codes — the
         values you'll actually see most often for Win32 LOB apps.
      2. A fallback to .NET's own Win32 system error lookup for HRESULT-style
         codes (0x8007xxxx) that aren't MSI-specific — this decodes many real
         Windows errors automatically without a hardcoded list.
      3. If genuinely undocumented, labels it "Unknown code" rather than
         guessing — do not trust a decoded reason you cannot verify.

    Then builds one self-contained HTML file (open it in any browser, no
    internet required) with a CSS pie chart, a ranked failure-reason table,
    and a per-device table.

    READ-ONLY — this script only reads report data.

    PRIVACY: Device names and usernames are masked by default in the HTML
    report (first 2 characters + asterisks). Pass -IncludeNames to show real
    values — this pulls potentially thousands of real employee names/devices,
    so do not share -IncludeNames output externally.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Requires:    Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement,
                 Microsoft.Graph.Reports PowerShell modules
    Permissions: DeviceManagementApps.Read.All (Application, for app-only auth)
                 or delegated with -Interactive
    Version:     1.0
    Date:        2026-07-27

.PARAMETER AppName
    Display name (or partial match) of the app to look up. If it matches more
    than one app object (common — Intune often has several versions/assignments
    sharing a display name), you'll be shown a numbered list and asked to pick
    exactly one, so a single lookup never silently turns into a full report
    covering every version. If omitted entirely (and -MaxApps is 0), the script
    asks for a name interactively — this is a single-app lookup tool by default,
    not a tenant-wide scan, since a full scan can take a long time.

.PARAMETER MaxApps
    Set to a number greater than 0 to scan multiple/all apps instead of doing a
    single-app lookup (bypasses the interactive prompt and the pick-one-of-many
    list). 0 = single-app lookup mode (the default).

.PARAMETER IncludeNames
    Show real device/user names in the report instead of masked placeholders.

.PARAMETER OutputPath
    Where to save the HTML report. Defaults to a timestamped file next to
    this script.

.EXAMPLE
    .\06-Win32AppFailureAnalysisReport.ps1
    Prompts for an app name, then (if it matches multiple app objects) asks you
    to pick exactly one before pulling its full install/failure history.

.EXAMPLE
    .\06-Win32AppFailureAnalysisReport.ps1 -AppName "Adobe Acrobat DC (64-bit) 24.002.20857"
    Looks up that one app directly. If the name still matches multiple app
    objects, shows a pick-list rather than silently analysing all of them.

.EXAMPLE
    .\06-Win32AppFailureAnalysisReport.ps1 -MaxApps 10 -IncludeNames
    Skips single-app mode entirely and scans the first 10 Win32 apps in the
    tenant, with real device/user names shown.
#>

[CmdletBinding()]
param(
    [string]$AppName,
    [int]$MaxApps = 0,
    [switch]$IncludeNames,
    [switch]$Interactive,
    [string]$OutputPath = (Join-Path $PSScriptRoot "reports\failure-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
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

# Well-documented Windows Installer (MSI) exit codes — the ones you actually see
# most often for Win32 LOB app failures. Source: Microsoft Learn "Error codes"
# for Windows Installer (learn.microsoft.com/windows/win32/msi/error-codes).
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
# app-install-error-codes reference (github.com/MicrosoftDocs/SupportArticles-docs,
# app-management folder) plus verified community/support threads for the
# 0x87D3xxxx IME content-delivery family (Microsoft Community Hub, Microsoft Learn Q&A).
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

    if ($msiErrorMap.ContainsKey([int]$ErrorCode)) {
        return $msiErrorMap[[int]$ErrorCode]
    }

    if ($HexErrorCode -and $intuneHexErrorMap.ContainsKey($HexErrorCode.ToUpper())) {
        return $intuneHexErrorMap[$HexErrorCode.ToUpper()]
    }

    # Try decoding as a Win32 HRESULT (0x8007xxxx = FACILITY_WIN32) using .NET's
    # own system error message table — this catches many real Windows errors
    # without needing a hardcoded list.
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

# ── Get target apps ──────────────────────────────────────────────────────────────
# This is a lookup-one-app tool by default. If -AppName isn't given, ask for it
# interactively rather than silently scanning the whole tenant (which can take a
# long time — some apps have tens of thousands of device records).
Write-Host "Fetching Win32 app list from Intune..." -ForegroundColor Cyan
$allApps = Get-MgDeviceAppManagementMobileApp -Filter "isOf('microsoft.graph.win32LobApp')"
Write-Host "  $($allApps.Count) Win32 app(s) in the tenant.`n" -ForegroundColor DarkGray

if (-not $AppName -and $MaxApps -eq 0) {
    $AppName = Read-Host "Enter an app name (or part of one) to look up — leave blank to scan every app in the tenant (slow)"
}

$matches = if ($AppName) { $allApps | Where-Object { $_.DisplayName -like "*$AppName*" } } else { $allApps }

if (-not $matches) {
    Write-Host "No apps matched '$AppName'." -ForegroundColor Red
    return
}

# If the name matches more than one app object (common — Intune often has several
# versions/assignments sharing a display name), make the user pick exactly ONE
# rather than silently pulling every match's full device history.
if ($AppName -and @($matches).Count -gt 1 -and $MaxApps -eq 0) {
    Write-Host "`n'$AppName' matched $(@($matches).Count) apps. Pick one:" -ForegroundColor Yellow
    $matchList = @($matches)
    for ($n = 0; $n -lt $matchList.Count; $n++) {
        Write-Host ("  [{0}] {1}  (id: {2})" -f ($n + 1), $matchList[$n].DisplayName, $matchList[$n].Id)
    }
    Write-Host "  [A] Analyse all $($matchList.Count) matches (slower)"
    $choice = Read-Host "`nEnter a number, or A for all"
    if ($choice -match '^[Aa]$') {
        $targetApps = $matchList
    } else {
        $idx = [int]$choice - 1
        if ($idx -lt 0 -or $idx -ge $matchList.Count) {
            Write-Host "Invalid choice." -ForegroundColor Red
            return
        }
        $targetApps = @($matchList[$idx])
    }
} else {
    $targetApps = @($matches)
}

if ($MaxApps -gt 0) { $targetApps = $targetApps | Select-Object -First $MaxApps }

Write-Host "`nAnalysing $($targetApps.Count) app(s): $($targetApps.DisplayName -join ', ')`n" -ForegroundColor Cyan

# ── Pull per-device rows (paginated) for every target app ────────────────────────
$pageSize = 999
$allRecords = [System.Collections.Generic.List[object]]::new()

$i = 0
foreach ($app in $targetApps) {
    $i++
    Write-Progress -Activity 'Pulling install records' -Status $app.DisplayName -PercentComplete (($i / $targetApps.Count) * 100)

    $skip = 0
    $totalRowCount = $null
    do {
        $outFile = Join-Path $env:TEMP "failure-analysis-$($app.Id)-$skip.json"
        try {
            Get-MgDeviceManagementReportDeviceAppInstallationStatusReport -Body @{
                filter = "(ApplicationId eq '$($app.Id)')"
                select = @('DeviceName', 'UserPrincipalName', 'InstallState', 'ErrorCode', 'HexErrorCode', 'Platform', 'AppVersion')
                skip   = $skip
                top    = $pageSize
            } -OutFile $outFile -ErrorAction Stop

            $report = Get-Content $outFile -Raw | ConvertFrom-Json
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue

            if ($null -eq $totalRowCount) { $totalRowCount = $report.TotalRowCount }

            # IMPORTANT: Graph returns report columns alphabetically sorted,
            # NOT in the order given in -select. Map column name -> index from
            # the report's own Schema every time rather than assuming order.
            $colIndex = @{}
            for ($c = 0; $c -lt $report.Schema.Count; $c++) { $colIndex[$report.Schema[$c].Column] = $c }

            foreach ($v in $report.Values) {
                $stateInt = [int]$v[$colIndex['InstallState']]
                $allRecords.Add([pscustomobject]@{
                    AppName      = $app.DisplayName
                    DeviceName   = $v[$colIndex['DeviceName']]
                    UserName     = $v[$colIndex['UserPrincipalName']]
                    InstallState = if ($installStateMap.ContainsKey($stateInt)) { $installStateMap[$stateInt] } else { "Unmapped($stateInt)" }
                    ErrorCode    = $v[$colIndex['ErrorCode']]
                    HexErrorCode = $v[$colIndex['HexErrorCode']]
                    Platform     = $v[$colIndex['Platform']]
                    AppVersion   = $v[$colIndex['AppVersion']]
                })
            }
            $skip += $pageSize
        } catch {
            Write-Host "  Skipped '$($app.DisplayName)': $($_.Exception.Message)" -ForegroundColor DarkYellow
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue
            break
        }
    } while ($skip -lt $totalRowCount)
}
Write-Progress -Activity 'Pulling install records' -Completed

Write-Host "Total device records pulled: $($allRecords.Count)`n" -ForegroundColor Cyan

# ── Install state distribution (for the pie chart) ──────────────────────────────
$stateCounts = $allRecords | Group-Object InstallState | Sort-Object Count -Descending |
    Select-Object @{n='State';e={$_.Name}}, Count

# ── Decode failure reasons and rank them ─────────────────────────────────────────
$failures = $allRecords | Where-Object { $_.InstallState -eq 'Failed' }
$failureReasons = $failures | ForEach-Object {
    $decoded = Get-FailureReason -ErrorCode $_.ErrorCode -HexErrorCode $_.HexErrorCode
    if ($decoded) {
        [pscustomobject]@{
            Reason   = $decoded.Reason
            Fix      = $decoded.Fix
            ErrorHex = $_.HexErrorCode
        }
    }
}

$rankedReasons = $failureReasons | Group-Object Reason, ErrorHex | Sort-Object Count -Descending |
    ForEach-Object {
        [pscustomobject]@{
            Reason = $_.Group[0].Reason
            Fix    = $_.Group[0].Fix
            Code   = $_.Group[0].ErrorHex
            Count  = $_.Count
        }
    }

Write-Host "=== Install State Distribution ===" -ForegroundColor Cyan
$stateCounts | Format-Table -AutoSize

Write-Host "=== Top Failure Reasons ===" -ForegroundColor Cyan
if ($rankedReasons) {
    $rankedReasons | Select-Object Count, Code, Reason | Format-Table -AutoSize -Wrap
} else {
    Write-Host "No failures found." -ForegroundColor Green
}

# ── Build an SVG donut chart ──────────────────────────────────────────────────
# Status colors (fixed, from the org's validated status palette) paired with an
# icon + label in the legend — color is never the only signal of identity.
$stateStyle = @{
    'Installed'       = @{ Color = '#0ca30c'; Icon = '&#10003;' }  # good
    'Failed'          = @{ Color = '#d03b3b'; Icon = '&#10007;' }  # critical
    'NotInstalled'    = @{ Color = '#fab219'; Icon = '&#9888;'  }  # warning
    'UninstallFailed' = @{ Color = '#d03b3b'; Icon = '&#10007;' }  # critical
    'PendingInstall'  = @{ Color = '#2a78d6'; Icon = '&#8635;'  }  # informational (categorical slot 1)
    'NotApplicable'   = @{ Color = '#9ca3af'; Icon = '&#8212;'  }  # neutral
    'Unknown'         = @{ Color = '#6b7280'; Icon = '&#63;'   }   # neutral
}

$totalCount = ($stateCounts | Measure-Object Count -Sum).Sum
$radius = 80
$circumference = 2 * [math]::PI * $radius
$cursor = 0
$donutSegments = [System.Collections.Generic.List[string]]::new()
$legendItems = [System.Collections.Generic.List[string]]::new()

foreach ($s in $stateCounts) {
    $pct = if ($totalCount -gt 0) { $s.Count / $totalCount } else { 0 }
    $style = if ($stateStyle.ContainsKey($s.State)) { $stateStyle[$s.State] } else { @{ Color = '#6b7280'; Icon = '&#8226;' } }
    $dashLength = $pct * $circumference
    $dashArray = "$dashLength $($circumference - $dashLength)"
    $dashOffset = -($cursor * $circumference)
    $donutSegments.Add("<circle r=`"$radius`" cx=`"110`" cy=`"110`" fill=`"transparent`" stroke=`"$($style.Color)`" stroke-width=`"32`" stroke-dasharray=`"$dashArray`" stroke-dashoffset=`"$dashOffset`" />")
    $legendItems.Add(@"
<div style='display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9'>
  <span style='width:12px;height:12px;border-radius:3px;background:$($style.Color);display:inline-block;flex-shrink:0'></span>
  <span style='font-size:14px;color:#111827;flex:1'>$($s.State)</span>
  <span style='font-size:14px;font-weight:700;color:#111827'>$($s.Count)</span>
  <span style='font-size:12px;color:#6b7280;width:44px;text-align:right'>$([math]::Round($pct*100,1))%</span>
</div>
"@)
    $cursor += $pct
}
$donutHtml = $donutSegments -join "`n"

$failedCount = [int]($stateCounts | Where-Object State -eq 'Failed' | Select-Object -ExpandProperty Count)
$installedCount = [int]($stateCounts | Where-Object State -eq 'Installed' | Select-Object -ExpandProperty Count)
$outcomeTotal = $installedCount + $failedCount + [int]($stateCounts | Where-Object State -eq 'NotInstalled' | Select-Object -ExpandProperty Count)
$overallFailRate = if ($outcomeTotal -gt 0) { [math]::Round(($failedCount / $outcomeTotal) * 100, 1) } else { 0 }
$topIssue = $rankedReasons | Select-Object -First 1

# ── Ranked failure reasons table ────────────────────────────────────────────────
$reasonRowsHtml = ($rankedReasons | ForEach-Object {
    $isVerified = $_.Reason -notmatch '^Not documented'
    $badgeColor = if ($isVerified) { '#0ca30c' } else { '#fab219' }
    $badgeLabel = if ($isVerified) { 'Documented' } else { 'Unverified' }
    @"
<tr>
  <td style='padding:14px 16px;border-bottom:1px solid #eef1f5;font-weight:800;color:#d03b3b;font-size:20px;vertical-align:top'>$($_.Count)</td>
  <td style='padding:14px 16px;border-bottom:1px solid #eef1f5;font-family:Consolas,monospace;font-size:12.5px;color:#111827;vertical-align:top;white-space:nowrap'>$($_.Code)</td>
  <td style='padding:14px 16px;border-bottom:1px solid #eef1f5;vertical-align:top'>
    <div style='display:flex;align-items:center;gap:8px;margin-bottom:6px'>
      <span style='font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#fff;background:$badgeColor;padding:2px 8px;border-radius:10px'>$badgeLabel</span>
    </div>
    <div style='color:#111827;font-size:14px;line-height:1.5;margin-bottom:6px'>$([System.Net.WebUtility]::HtmlEncode($_.Reason))</div>
    <div style='color:#047857;font-size:13px;line-height:1.5;background:#f0fdf4;border-left:3px solid #0ca30c;padding:8px 12px;border-radius:0 6px 6px 0'><strong>Fix:</strong> $([System.Net.WebUtility]::HtmlEncode($_.Fix))</div>
  </td>
</tr>
"@
}) -join "`n"

# ── Per-device detail table ──────────────────────────────────────────────────────
$deviceRowsHtml = ($allRecords | Sort-Object InstallState | ForEach-Object {
    $maskedDevice = Get-MaskedName $_.DeviceName
    $maskedUser   = Get-MaskedName $_.UserName
    $style = if ($stateStyle.ContainsKey($_.InstallState)) { $stateStyle[$_.InstallState] } else { @{ Color = '#6b7280'; Icon = '&#8226;' } }
    @"
<tr>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;color:#374151'>$([System.Net.WebUtility]::HtmlEncode($_.AppName))</td>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;color:#374151'>$([System.Net.WebUtility]::HtmlEncode($maskedDevice))</td>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;color:#374151'>$([System.Net.WebUtility]::HtmlEncode($maskedUser))</td>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9'><span style='color:$($style.Color);font-weight:700;font-size:13px'>$($style.Icon) $($_.InstallState)</span></td>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;font-family:Consolas,monospace;font-size:12px;color:#6b7280'>$($_.HexErrorCode)</td>
  <td style='padding:9px 14px;border-bottom:1px solid #f1f5f9;color:#6b7280;font-size:12.5px'>$($_.Platform)</td>
</tr>
"@
}) -join "`n"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Win32 App Failure Analysis — EndpointWeekly</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',Outfit,-apple-system,sans-serif;background:#f8fafc;color:#111827;margin:0;padding:0 0 48px}
.hero{background:linear-gradient(135deg,#064e3b,#059669);padding:40px 32px;color:#fff}
.hero-inner{max-width:1100px;margin:0 auto}
.hero h1{font-size:26px;margin:0 0 6px;font-weight:700}
.hero .sub{color:#d1fae5;font-size:13.5px}
.wrap{max-width:1100px;margin:-24px auto 0;padding:0 32px}
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat{background:#fff;border-radius:12px;padding:18px 20px;box-shadow:0 4px 16px rgba(0,0,0,.08)}
.stat .n{font-size:26px;font-weight:800;color:#111827;line-height:1.1}
.stat .l{font-size:12px;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.03em;font-weight:600}
.card{background:#fff;border-radius:14px;padding:28px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04)}
h2{font-size:17px;margin:0 0 18px;font-weight:700;color:#052e16;display:flex;align-items:center;gap:8px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;padding:10px 14px;background:#064e3b;color:#fff;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;font-weight:700}
th:first-child{border-radius:8px 0 0 0}
th:last-child{border-radius:0 8px 0 0}
.donut-wrap{display:flex;gap:40px;align-items:center;flex-wrap:wrap}
.donut-center{font-size:13px;color:#6b7280;text-anchor:middle}
.legend{flex:1;min-width:220px}
.table-scroll{overflow-x:auto}
@media(max-width:640px){.hero{padding:28px 18px}.wrap{padding:0 16px}.card{padding:18px}}
</style>
</head>
<body>

<div class="hero">
  <div class="hero-inner">
    <h1>Win32 App Failure Analysis</h1>
    <div class="sub">Generated $(Get-Date -Format 'dd MMM yyyy, HH:mm') &middot; $($targetApps.Count) app(s) analysed &middot; $($allRecords.Count) device records</div>
  </div>
</div>

<div class="wrap">

  <div class="stat-row">
    <div class="stat"><div class="n">$($allRecords.Count)</div><div class="l">Device records</div></div>
    <div class="stat"><div class="n" style="color:#0ca30c">$installedCount</div><div class="l">Installed</div></div>
    <div class="stat"><div class="n" style="color:#d03b3b">$failedCount</div><div class="l">Failed</div></div>
    <div class="stat"><div class="n">$overallFailRate%</div><div class="l">Fail rate (of outcomes)</div></div>
  </div>

  <div class="card">
    <h2>&#128202; Install State Distribution</h2>
    <div class="donut-wrap">
      <svg width="220" height="220" viewBox="0 0 220 220" style="transform:rotate(-90deg);flex-shrink:0">
        $donutHtml
      </svg>
      <div class="legend">$($legendItems -join "`n")</div>
    </div>
  </div>

  <div class="card">
    <h2>&#128269; Top Failure Reasons (ranked, with fixes)</h2>
    $(if ($rankedReasons) {
"<div class='table-scroll'><table>
      <tr><th style='width:70px'>Count</th><th style='width:120px'>Code</th><th>Reason &amp; Fix</th></tr>
      $reasonRowsHtml
    </table></div>"
    } else {
"<div style='color:#0ca30c;font-weight:600'>&#10003; No failures found across the checked apps.</div>"
    })
  </div>

  <div class="card">
    <h2>&#128187; Per-Device Detail $(if (-not $IncludeNames) { '<span style="font-size:12px;font-weight:400;color:#9ca3af">(device &amp; user names masked)</span>' })</h2>
    <div class="table-scroll">
    <table>
      <tr><th>App</th><th>Device</th><th>User</th><th>State</th><th>Error</th><th>Platform</th></tr>
      $deviceRowsHtml
    </table>
    </div>
  </div>

  <div style="text-align:center;color:#9ca3af;font-size:12px;padding:16px 0">
    Generated by 06-Win32AppFailureAnalysisReport.ps1 &middot; endpointweekly.com
  </div>

</div>
</body></html>
"@

$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "`nHTML report saved: $OutputPath" -ForegroundColor Green
try { Start-Process $OutputPath } catch {}
