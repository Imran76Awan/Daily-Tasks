<#
.SYNOPSIS
    Checks the current SharePoint Server farm build version against the August 2026 CU minimum threshold.

.DESCRIPTION
    Queries the SharePoint farm build number using Get-SPFarm and reports whether each server
    in the farm has been upgraded (NeedsUpgrade = False) after applying the August 2026
    Cumulative Update. This script is the companion to the EndpointWeekly blog post on
    CVE-2026-55040 and the August 2026 Patch Tuesday guidance.

    Run on any SharePoint Application Server using the SharePoint Management Shell.
    The SharePoint snap-in is added automatically if not already loaded.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/windows-august-2026-patch-tuesday.html
    Created : 2026-08-07
    Version : 1.0

    Prerequisites:
    - Run on a SharePoint Server (SE, 2019, or 2016 Application or WFE)
    - Requires SharePoint farm administrator rights
    - Must be run from the SharePoint Management Shell or a session with the snap-in loaded

.EXAMPLE
    .\Get-SharePointBuildVersion.ps1

    Example output:
    SharePoint Farm Build : 16.0.17726.20034
    Build appears patched - verify KB number against MSRC advisory

    Name          NeedsUpgrade
    ----          ------------
    SP-WFE01      False
    SP-APP01      False
#>

[CmdletBinding()]
param()

# Load the SharePoint snap-in if not already present
if (-not (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)) {
    try {
        Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop
    }
    catch {
        Write-Error "Could not load the SharePoint snap-in. Run this script on a SharePoint server using the SharePoint Management Shell."
        exit 1
    }
}

# Retrieve farm build version
$farm  = Get-SPFarm
$build = $farm.BuildVersion

Write-Host ""
Write-Host "SharePoint Farm Build : $($build.ToString())" -ForegroundColor Cyan

# Minimum safe builds for August 2026 CU (KB numbers published 12 August 2026)
# Update these thresholds once the official advisory confirms the KB numbers.
# SharePoint SE    : 16.0.17726.20000 or later
# SharePoint 2019  : 16.0.10415.20000 or later
# SharePoint 2016  : 16.0.5466.1000   or later

if ($build.Major -eq 16 -and $build.Build -lt 17726) {
    Write-Host "VULNERABLE - apply the August 2026 Cumulative Update immediately" -ForegroundColor Red
    Write-Host "CVE-2026-55040 (CVSS 9.1) - JWT token validation bypass - is exploitable on this build." -ForegroundColor Red
}
else {
    Write-Host "Build appears patched - verify the KB number against the August 2026 MSRC advisory." -ForegroundColor Green
}

Write-Host ""
Write-Host "Farm server upgrade status:" -ForegroundColor Cyan

# Check all servers in the farm for mixed-version state
# NeedsUpgrade = True means psconfig.exe has not completed on that server
Get-SPServer | Select-Object Name, NeedsUpgrade | Format-Table -AutoSize

Write-Host "If any server shows NeedsUpgrade = True, run on that server:" -ForegroundColor Yellow
Write-Host "  psconfig.exe -cmd upgrade -inplace b2b -wait" -ForegroundColor Yellow
Write-Host ""
