<#
.SYNOPSIS
    Collects the Windows Autopilot hardware hash (device fingerprint) and exports it to CSV.

.DESCRIPTION
    Installs the Get-WindowsAutoPilotInfo script from PSGallery (if not already installed),
    sets the process execution policy, and exports the hardware hash for this device to a CSV
    file in C:\HWID\. The CSV can then be imported into the Microsoft Intune admin center
    (Devices > Windows > Enrollment > Windows Autopilot > Import) to register the device for
    Autopilot deployment.

    If the hardware hash CSV import fails with a Base64 error, use the validation command
    shown in the .NOTES section to check the hash before re-importing.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/autopilot-mdm-log-collection-decoding-guide.html
    Created : 2026-08-07
    Version : 1.0

    Prerequisites:
    - Must be run as Administrator
    - PowerShell execution policy must allow script installation from PSGallery
    - Internet access required to install Get-WindowsAutoPilotInfo if not already present

    Import location in Intune:
    Devices > Windows > Enrollment > Windows Autopilot > Devices > Import
    (select the AutoPilotHWID.csv file exported by this script)

    Base64 hash validation (run if import fails):
    [System.Text.Encoding]::ascii.getstring([System.Convert]::FromBase64String("HASH_HERE"))
    If this throws "Invalid length for a Base-64 char array", the hash has a padding issue.
    Add one or two = characters at the end of the hash string and retry the import.

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1

    Exports AutoPilotHWID.csv to C:\HWID\AutoPilotHWID.csv

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1 -OutputPath "D:\Staging"

    Exports AutoPilotHWID.csv to D:\Staging\AutoPilotHWID.csv
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\HWID"
)

# Check for admin rights
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Re-launch PowerShell as Administrator and try again."
    exit 1
}

# Create output directory if needed
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Cyan
}

# Add PSGallery scripts path to process PATH
$psScriptsPath = "$env:ProgramFiles\WindowsPowerShell\Scripts"
if ($env:Path -notlike "*$psScriptsPath*") {
    $env:Path += ";$psScriptsPath"
}

# Set execution policy for current process only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force

# Install Get-WindowsAutoPilotInfo if not already available
Write-Host "Checking for Get-WindowsAutoPilotInfo script..." -ForegroundColor Cyan
$installed = Get-InstalledScript -Name Get-WindowsAutoPilotInfo -ErrorAction SilentlyContinue
if (-not $installed) {
    Write-Host "Installing Get-WindowsAutoPilotInfo from PSGallery..." -ForegroundColor Cyan
    try {
        Install-Script -Name Get-WindowsAutoPilotInfo -Force -ErrorAction Stop
        Write-Host "Script installed." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Get-WindowsAutoPilotInfo: $_"
        Write-Error "Check internet connectivity and PSGallery access, then retry."
        exit 1
    }
}
else {
    Write-Host "Get-WindowsAutoPilotInfo v$($installed.Version) already installed." -ForegroundColor Green
}

# Export the hardware hash
$csvPath = Join-Path $OutputPath "AutoPilotHWID.csv"

Write-Host ""
Write-Host "Collecting hardware hash..." -ForegroundColor Cyan
try {
    Get-WindowsAutoPilotInfo -OutputFile $csvPath -ErrorAction Stop
}
catch {
    Write-Error "Get-WindowsAutoPilotInfo failed: $_"
    exit 1
}

if (Test-Path $csvPath) {
    Write-Host ""
    Write-Host "Hardware hash exported." -ForegroundColor Green
    Write-Host "CSV file : $csvPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. In Intune Admin Center go to:" -ForegroundColor White
    Write-Host "     Devices > Windows > Enrollment > Windows Autopilot > Devices > Import" -ForegroundColor White
    Write-Host "  2. Select $csvPath and upload" -ForegroundColor White
    Write-Host "  3. Assign an Autopilot deployment profile to the device" -ForegroundColor White
    Write-Host "  4. If import fails with a Base64 error, validate the hash with:" -ForegroundColor White
    Write-Host "     [System.Convert]::FromBase64String('HASH_HERE')" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Error "CSV file was not created. Check above for errors."
    exit 1
}
