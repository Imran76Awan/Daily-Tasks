<#
.SYNOPSIS
    Collects a complete Autopilot and MDM diagnostic cab file covering all four log areas.

.DESCRIPTION
    Wraps MdmDiagnosticsTool.exe to collect Autopilot, TPM, DeviceProvisioning, and
    DeviceEnrollment logs in a single timestamped cab file. Run this on a device that is
    stuck during OOBE (via Shift+F10 in a command prompt) or on any managed Windows device
    where you need to diagnose an MDM enrollment or ESP failure.

    The cab is saved to C:\Users\Public\Documents\MDMDiagnostics\ with a timestamp so
    consecutive runs do not overwrite each other.

    After collection, open the cab and start with MdmDiagReport_RegistryDump.reg to
    find InstallationState = 4 entries, then MDMDiagHtmlReport.html for a policy summary.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/autopilot-mdm-log-collection-decoding-guide.html
    Created : 2026-08-07
    Version : 1.0

    Prerequisites:
    - Must be run as Administrator (or from an elevated Shift+F10 prompt during OOBE)
    - MdmDiagnosticsTool.exe is built in to Windows 10 1809 and later
    - For Windows 10 earlier than 1809, use licensingdiag.exe instead

.EXAMPLE
    .\Collect-AutopilotLogs.ps1

    Saves cab to: C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport_20260807_143022.cab

.EXAMPLE
    .\Collect-AutopilotLogs.ps1 -OutputPath "D:\Logs"

    Saves cab to D:\Logs\MDMDiagReport_20260807_143022.cab
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\Users\Public\Documents\MDMDiagnostics"
)

# Check for admin rights
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script is not running as Administrator. MdmDiagnosticsTool.exe may produce incomplete output."
    Write-Warning "Re-launch PowerShell as Administrator or, during OOBE, use the elevated Shift+F10 prompt."
}

# Check that MdmDiagnosticsTool.exe exists (Windows 10 1809+)
$toolPath = "$env:windir\System32\MdmDiagnosticsTool.exe"
if (-not (Test-Path $toolPath)) {
    Write-Error "MdmDiagnosticsTool.exe not found at $toolPath."
    Write-Error "This device may be running Windows 10 earlier than 1809. Use licensingdiag.exe instead."
    exit 1
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Cyan
}

# Build timestamped output filename
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$cabName    = "MDMDiagReport_$timestamp.cab"
$cabPath    = Join-Path $OutputPath $cabName

Write-Host ""
Write-Host "Collecting Autopilot MDM diagnostic logs..." -ForegroundColor Cyan
Write-Host "Areas: Autopilot, TPM, DeviceProvisioning, DeviceEnrollment" -ForegroundColor Cyan
Write-Host "Output: $cabPath" -ForegroundColor Cyan
Write-Host ""

# Run MdmDiagnosticsTool.exe with all four areas
$args = "-area Autopilot;TPM;DeviceProvisioning;DeviceEnrollment -cab `"$cabPath`""
$process = Start-Process -FilePath $toolPath -ArgumentList $args -Wait -PassThru -NoNewWindow

if ($process.ExitCode -eq 0 -and (Test-Path $cabPath)) {
    $cabSize = [math]::Round((Get-Item $cabPath).Length / 1KB, 1)
    Write-Host "Collection complete." -ForegroundColor Green
    Write-Host ""
    Write-Host "Cab file : $cabPath ($cabSize KB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Open the cab and start with MdmDiagReport_RegistryDump.reg" -ForegroundColor White
    Write-Host "     Search for 'InstallationState = 4' to find the blocking app in ESP" -ForegroundColor White
    Write-Host "  2. Open MDMDiagHtmlReport.html for a policy and certificate summary" -ForegroundColor White
    Write-Host "  3. Run Get-AutopilotDiagnostics -AllSessions -CABFile '$cabPath'" -ForegroundColor White
    Write-Host "     to get a human-readable session analysis" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Error "MdmDiagnosticsTool.exe exited with code $($process.ExitCode) or the cab file was not created."
    Write-Error "Ensure the script is running as Administrator."
    exit 1
}
