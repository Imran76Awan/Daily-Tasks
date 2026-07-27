<#
.SYNOPSIS
    Reports Win32 app deployment status across your fleet via Microsoft Graph.

.DESCRIPTION
    Lists every Win32 app (win32LobApp) in your Intune tenant and, for each one,
    pulls the install status report and summarises how many devices are
    Installed, Failed, Not Installed, Uninstall Failed, or Unknown — so failures
    are easy to spot at a glance across your whole fleet.

    Uses Get-MgDeviceManagementReportDeviceAppInstallationStatusReport (the
    correct modern report). The older Get-MgDeviceAppManagementMobileAppDeviceStatuses
    /deviceStatuses navigation property this was originally written against was
    deprecated by Microsoft in May 2023 and no longer works — this version calls
    the replacement report API instead.

    READ-ONLY — this script only reads app and device status data.

    PRIVACY: By default this only prints aggregate counts per install state — no
    device names or usernames. Pass -Detailed to see per-device rows (still
    masks names unless you also pass -IncludeNames). This report can return
    thousands of rows with real employee names and device names — do not paste
    raw -IncludeNames output anywhere public.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Requires:    Microsoft.Graph.Authentication, Microsoft.Graph.Reports PowerShell modules
    Permissions: DeviceManagementApps.Read.All (Application, for app-only auth)
                 or delegated with -Interactive
    Version:     2.0
    Date:        2026-07-27

.PARAMETER Detailed
    Show per-device rows instead of just aggregate counts per app.

.PARAMETER IncludeNames
    Only relevant with -Detailed. Shows real device/user names instead of masked
    placeholders. Off by default — this data is sensitive.

.PARAMETER Interactive
    Sign in interactively as the current user instead of using the app
    registration's certificate.

.EXAMPLE
    .\03-CheckWin32AppStatus.ps1
    Connects with app-only certificate auth and prints install-state counts
    (Installed / Failed / Not Installed / etc.) for every Win32 app in the tenant.
    Safe to screenshot — no device or user names shown.

.EXAMPLE
    .\03-CheckWin32AppStatus.ps1 -Detailed
    Same, but also lists per-device rows with device/user names masked.

.EXAMPLE
    .\03-CheckWin32AppStatus.ps1 -Detailed -IncludeNames
    Full per-device detail with real names. Do not share this output externally.
#>

[CmdletBinding()]
param(
    [switch]$Detailed,
    [switch]$IncludeNames,
    [switch]$Interactive,
    [int]$MaxApps = 0   # 0 = all apps. Set a number to limit how many apps are checked (useful for a quick test — a full tenant can have hundreds of Win32 apps and each one is a separate report call).
)

$ErrorActionPreference = 'Stop'

# ── Module version pin ─────────────────────────────────────────────────────────
# If multiple versions of the Graph SDK submodules are installed side by side,
# PowerShell can auto-load a newer Microsoft.Graph.Authentication than the
# other Graph modules were built against, causing:
#   "Could not load file or assembly 'Microsoft.Graph.Authentication.Core...'"
# Pin all three to the same version to avoid this. Adjust below to whatever
# your latest matching set is (Get-Module -ListAvailable Microsoft.Graph.*).
$graphModuleVersion = '2.27.0'
Import-Module Microsoft.Graph.Authentication    -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.DeviceManagement  -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Reports           -RequiredVersion $graphModuleVersion -ErrorAction SilentlyContinue

# ── Auth settings (app-only certificate) ──────────────────────────────────────
$tenantId   = 'YOUR-TENANT-ID'        # e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$clientId   = 'YOUR-APP-CLIENT-ID'    # App registration (client) ID from Entra
$thumbprint = 'YOUR-CERT-THUMBPRINT'  # Certificate thumbprint on the app registration

# ── Connect ───────────────────────────────────────────────────────────────────
if ($Interactive) {
    Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome
} else {
    Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -NoWelcome
}

# installState integer -> readable label
# Values per Microsoft's official resultantAppState enum documentation:
# https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-resultantappstate
$installStateMap = @{
    -1 = 'NotApplicable'    # App doesn't apply to this device (e.g. out of assignment scope)
    1  = 'Installed'        # Installed with no errors
    2  = 'Failed'           # Failed to install
    3  = 'NotInstalled'     # Not installed
    4  = 'UninstallFailed'  # Failed to uninstall
    5  = 'PendingInstall'   # Install is in progress
    99 = 'Unknown'          # Status unknown
}

function Get-MaskedName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '(none)' }
    if ($IncludeNames) { return $Name }
    # Keep first 2 chars as a hint, mask the rest — enough to spot patterns without exposing PII
    if ($Name.Length -le 2) { return '**' }
    return $Name.Substring(0, 2) + ('*' * ($Name.Length - 2))
}

# Get every Win32 app in the tenant
$win32Apps = Get-MgDeviceAppManagementMobileApp -Filter "isOf('microsoft.graph.win32LobApp')"
if ($MaxApps -gt 0) { $win32Apps = $win32Apps | Select-Object -First $MaxApps }
Write-Host "Checking $($win32Apps.Count) Win32 app(s).`n" -ForegroundColor Cyan

# Graph caps this report at ~1000 rows per call — page through with skip/top to get everything.
$pageSize = 999

foreach ($app in $win32Apps) {
    Write-Host "=== $($app.DisplayName) ===" -ForegroundColor Cyan

    $allRows = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $totalRowCount = $null

    try {
        $colIndex = $null
        do {
            $outFile = Join-Path $env:TEMP "app-install-status-$($app.Id)-$skip.json"
            Get-MgDeviceManagementReportDeviceAppInstallationStatusReport -Body @{
                filter = "(ApplicationId eq '$($app.Id)')"
                select = @('DeviceName', 'UserPrincipalName', 'InstallState', 'LastModifiedDateTime')
                skip   = $skip
                top    = $pageSize
            } -OutFile $outFile -ErrorAction Stop

            $report = Get-Content $outFile -Raw | ConvertFrom-Json
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue

            if ($null -eq $totalRowCount) { $totalRowCount = $report.TotalRowCount }
            if ($null -eq $colIndex) {
                # IMPORTANT: Graph returns report columns alphabetically sorted,
                # NOT in the order given in -select. Map column name -> index
                # from the report's own Schema rather than assuming order.
                $colIndex = @{}
                for ($c = 0; $c -lt $report.Schema.Count; $c++) { $colIndex[$report.Schema[$c].Column] = $c }
            }
            if ($report.Values) { $report.Values | ForEach-Object { $allRows.Add($_) } }

            $skip += $pageSize
        } while ($skip -lt $totalRowCount)

        if ($allRows.Count -eq 0) {
            Write-Host "  No device install data for this app." -ForegroundColor DarkGray
            continue
        }

        $rows = $allRows | ForEach-Object {
            $stateInt = [int]$_[$colIndex['InstallState']]
            [pscustomobject]@{
                DeviceName   = $_[$colIndex['DeviceName']]
                InstallState = if ($installStateMap.ContainsKey($stateInt)) { $installStateMap[$stateInt] } else { "Unmapped($stateInt)" }
                LastModified = $_[$colIndex['LastModifiedDateTime']]
                UserName     = $_[$colIndex['UserPrincipalName']]
            }
        }

        Write-Host ("  Total device records: {0}" -f $rows.Count) -ForegroundColor Yellow
        $rows | Group-Object InstallState | Sort-Object Count -Descending |
            Select-Object @{n='InstallState';e={$_.Name}}, Count | Format-Table -AutoSize

        if ($Detailed) {
            $rows | ForEach-Object {
                [pscustomobject]@{
                    DeviceName   = Get-MaskedName $_.DeviceName
                    UserName     = Get-MaskedName $_.UserName
                    InstallState = $_.InstallState
                    LastModified = $_.LastModified
                }
            } | Sort-Object InstallState | Format-Table -AutoSize
        }
    } catch {
        Write-Host "  Could not retrieve report for this app: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item $outFile -Force -ErrorAction SilentlyContinue
    }
}
