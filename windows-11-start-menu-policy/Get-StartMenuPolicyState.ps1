<#
.SYNOPSIS
    Reports the current state of all Windows 11 Start menu MDM/CSP policies on the local device.

.DESCRIPTION
    Reads the MDM policy registry hive and the GPO policy hive to show which Start menu
    policies are currently applied — whether via Intune CSP or Group Policy.
    Useful for verifying that an Intune custom OMA-URI profile has landed correctly.

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-11-start-menu-policy-settings-intune-csp.html
    Run as: Standard user or SYSTEM (no elevation required for registry reads)
    Tested on: Windows 11 22H2, 23H2, 24H2

.EXAMPLE
    .\Get-StartMenuPolicyState.ps1
    # Outputs a table of all detected Start menu policy values

.EXAMPLE
    .\Get-StartMenuPolicyState.ps1 -ExportCsv
    # Exports results to StartMenuPolicyState_YYYYMMDD.csv
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$OutputPath = ".\StartMenuPolicyState_$(Get-Date -Format 'yyyyMMdd').csv"
)

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── MDM (Intune CSP) hive — Device scope ─────────────────────────────────────
$mdmStartPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start"
$mdmSearchPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Search"
$mdmLogonPath  = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon"

$startPolicies = @(
    "ConfigureStartPins", "DisableContextMenus",
    "HideRecentlyAddedApps", "HideRecentJumplists",
    "HideRecommendedPersonalizedSites", "HideRecommendedSection",
    "HideAppList", "HideCategoryView", "HideFrequentlyUsedApps",
    "ShowOrHideMostUsedApps",
    "HideChangeAccountSettings", "HideSignOut", "HideSwitchAccount",
    "HideUserTile", "HideLock",
    "AllowPinnedFolderDocuments", "AllowPinnedFolderDownloads",
    "AllowPinnedFolderFileExplorer", "AllowPinnedFolderMusic",
    "AllowPinnedFolderNetwork", "AllowPinnedFolderPersonalFolder",
    "AllowPinnedFolderPictures", "AllowPinnedFolderSettings",
    "AllowPinnedFolderVideos",
    "HideHibernate", "HidePowerButton", "HideRestart", "HideShutDown", "HideSleep"
)

if (Test-Path $mdmStartPath) {
    $props = Get-ItemProperty -Path $mdmStartPath -ErrorAction SilentlyContinue
    foreach ($policy in $startPolicies) {
        $val = $props.$policy
        if ($null -ne $val) {
            $results.Add([PSCustomObject]@{
                Policy   = $policy
                Value    = $val
                Source   = "MDM (Intune CSP)"
                CSPNode  = "Start/$policy"
            })
        }
    }
}

# DisableSearch is under Search node
if (Test-Path $mdmSearchPath) {
    $searchProps = Get-ItemProperty -Path $mdmSearchPath -ErrorAction SilentlyContinue
    if ($null -ne $searchProps.DisableSearch) {
        $results.Add([PSCustomObject]@{
            Policy  = "DisableSearch"
            Value   = $searchProps.DisableSearch
            Source  = "MDM (Intune CSP)"
            CSPNode = "Search/DisableSearch"
        })
    }
}

# HideFastUserSwitching is under WindowsLogon node
if (Test-Path $mdmLogonPath) {
    $logonProps = Get-ItemProperty -Path $mdmLogonPath -ErrorAction SilentlyContinue
    if ($null -ne $logonProps.HideFastUserSwitching) {
        $results.Add([PSCustomObject]@{
            Policy  = "HideFastUserSwitching"
            Value   = $logonProps.HideFastUserSwitching
            Source  = "MDM (Intune CSP)"
            CSPNode = "WindowsLogon/HideFastUserSwitching"
        })
    }
}

# ── GPO hive — for policies that only support Group Policy ───────────────────
$gpoExplorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (Test-Path $gpoExplorerPath) {
    $gpoProps = Get-ItemProperty -Path $gpoExplorerPath -ErrorAction SilentlyContinue
    $gpoPolicies = @("NoStartMenuMorePrograms", "NoPinningToStartMenu",
                     "NoChangeStartMenu", "StartMenuLogOff")
    foreach ($p in $gpoPolicies) {
        $val = $gpoProps.$p
        if ($null -ne $val) {
            $results.Add([PSCustomObject]@{
                Policy  = $p
                Value   = $val
                Source  = "GPO (Group Policy)"
                CSPNode = "GPO-only — not deployable via Intune"
            })
        }
    }
}

# ── Output ───────────────────────────────────────────────────────────────────
if ($results.Count -eq 0) {
    Write-Host "No Start menu policies detected. No Intune CSP or GPO settings are applied on this device." -ForegroundColor Yellow
} else {
    Write-Host "`n=== Start Menu Policy State ===" -ForegroundColor Cyan
    $results | Format-Table Policy, Value, Source, CSPNode -AutoSize -Wrap
    Write-Host "Total policies applied: $($results.Count)" -ForegroundColor Green
}

if ($ExportCsv) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $OutputPath" -ForegroundColor Green
}
