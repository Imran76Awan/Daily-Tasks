<#
.SYNOPSIS
    Converts a Win32 app source folder into the .intunewin package format required
    for upload to Microsoft Intune.

.DESCRIPTION
    Wraps the Microsoft Win32 Content Prep Tool (IntuneWinAppUtil.exe). Every Win32
    app deployed through Intune must be packaged this way before upload — the tool
    compresses and encrypts the source folder into a single .intunewin file that
    Intune can distribute securely via the Intune Management Extension (IME).

    Download IntuneWinAppUtil.exe from:
    https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Requires:    IntuneWinAppUtil.exe (download separately, path set below)
    Version:     1.0
    Date:        2026-07-24

.EXAMPLE
    .\01-PackageWin32App.ps1
    Packages the sample 7-Zip installer into an .intunewin file.
#>

[CmdletBinding()]
param()

# ── Configure these paths for your app ────────────────────────────────────────
$sourcePath  = "C:\AppPackages\7zip"          # Folder containing setup files
$setupFile   = "7z2301-x64.msi"               # Primary installer filename
$outputPath  = "C:\IntunePackages"            # Where .intunewin will be saved
$prepTool    = "C:\Tools\IntuneWinAppUtil.exe" # Path to the downloaded prep tool

& $prepTool -c $sourcePath -s $setupFile -o $outputPath -q

Write-Host "Package created: $outputPath\$($setupFile -replace '\.\w+$','.intunewin')"
