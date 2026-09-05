<#
.SYNOPSIS
    Flags devices at risk of the KB5120998 mouse cursor personalization bug -
    installed update plus a non-English system locale.

.DESCRIPTION
    Microsoft's Windows release health dashboard confirms that KB5120998
    (released August 27, 2026) resets mouse cursor personalization settings
    on Windows 11 24H2 and 25H2 devices, and that the root cause is specific
    to non-English Windows installations - the setting fails to load in
    those locales and falls back to a default value. Reapplying the setting
    does not fix it, and there is no code fix or official workaround yet.

    This script does not detect whether the symptom has actually occurred on
    a device (it can be intermittent) - it flags devices that meet BOTH
    documented risk conditions, so IT can prioritize communication or a
    temporary uninstall for the devices where the bug is actually possible.

    Read-only. Makes no changes to the device.

.PARAMETER CsvPath
    Optional path to export the result as CSV.

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5120998-mouse-cursor-personalization-reset-non-english.html

    Exit 0 = Device is not at risk (update not installed, or locale is English)
    Exit 1 = Device meets both risk conditions (KB5120998 installed AND non-English locale)
    Exit 2 = Script error

.EXAMPLE
    .\Get-KB5120998CursorRiskReport.ps1
    Check the local device and print the result.

.EXAMPLE
    .\Get-KB5120998CursorRiskReport.ps1 -CsvPath "C:\Temp\kb5120998-risk.csv"
    Same check, appending the result as one row to a CSV - run this across a
    fleet via RMM or an Intune platform script to build a combined report.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

try {
    $kb = Get-HotFix -Id "KB5120998" -ErrorAction SilentlyContinue
    $kbInstalled = $null -ne $kb
    $installedOn = if ($kb) { $kb.InstalledOn } else { $null }

    $locale = Get-WinSystemLocale
    $isEnglish = $locale.Name -like "en-*"

    $atRisk = $kbInstalled -and (-not $isEnglish)

    $result = [PSCustomObject]@{
        ComputerName  = $env:COMPUTERNAME
        KBInstalled   = $kbInstalled
        InstalledOn   = $installedOn
        SystemLocale  = $locale.Name
        AtRisk        = $atRisk
        CheckedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }

    $result | Format-Table -AutoSize

    if ($CsvPath) {
        $csvDir = Split-Path -Path $CsvPath -Parent
        if ($csvDir -and -not (Test-Path $csvDir)) {
            New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        }
        $writeHeader = -not (Test-Path $CsvPath)
        $result | Export-Csv -Path $CsvPath -NoTypeInformation -Append:(!$writeHeader) -Force
        Write-Host "Result appended to $CsvPath"
    }

    if ($atRisk) {
        exit 1
    } else {
        exit 0
    }
} catch {
    Write-Host "ERROR: $_"
    exit 2
}
