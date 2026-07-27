<#
.SYNOPSIS
    Custom detection script template for a Win32 app in Intune.

.DESCRIPTION
    Intune will not mark a Win32 app as installed until this detection rule
    passes. Checks for the presence of a target executable AND that its file
    version meets the minimum required version — checking the version, not just
    file existence, avoids false positives from a stale/older install.

    Deploy this as the "Custom detection script" under the Win32 app's Detection
    rules. Exit code 0 = detected (installed). Exit code 1 = not found (not
    installed).

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Run context: SYSTEM (Intune runs detection scripts as SYSTEM)
    Version:     1.0
    Date:        2026-07-24

.EXAMPLE
    Deployed as-is via Intune > Apps > Win32 app > Detection rules > Use a custom
    detection script.
#>

# Custom detection script — exits 0 (detected) or 1 (not found)
$appPath = "C:\Program Files\7-Zip\7z.exe"
$minVersion = [version]"23.01.0.0"

if (Test-Path $appPath) {
    $fileVer = [version](Get-Item $appPath).VersionInfo.FileVersion
    if ($fileVer -ge $minVersion) {
        Write-Output "Detected: $fileVer"
        exit 0
    }
}
exit 1
