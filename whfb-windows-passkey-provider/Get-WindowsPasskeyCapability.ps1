<#
.SYNOPSIS
    Read-only report of this device's Windows passkey capability and readiness.

.DESCRIPTION
    Changes nothing. Reports the Windows build/feature update and maps it to
    passkey capability (22H2 = native passkey management; 24H2 = passkey privacy
    consent controls), whether Windows Hello is provisioned (the unlock factor
    for Windows-provided passkeys), and a reminder about the Bluetooth dependency
    for cross-device passkey sign-in.

.EXAMPLE
    .\Get-WindowsPasskeyCapability.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-windows-passkey-provider.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param()

$build = [int]([System.Environment]::OSVersion.Version.Build)
$featureUpdate =
    if ($build -ge 26100) { '24H2 or later' }
    elseif ($build -ge 22621) { '22H2 / 23H2' }
    elseif ($build -ge 22000) { '21H2' }
    else { 'Windows 10 / older' }

$nativeMgmt = ($build -ge 22621)   # 22H2 native passkey management (with KB5030310)
$privacyConsent = ($build -ge 26100) # 24H2 passkey privacy consent controls

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

# Bluetooth service present (needed for cross-device passkey sign-in)
$btService = Get-Service bthserv -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '  Windows Passkey Capability' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  OS build                        : {0}  ({1})' -f $build, $featureUpdate)
Write-Host ('  Native passkey management (22H2): {0}' -f $nativeMgmt)
Write-Host ('  Passkey privacy consent (24H2)  : {0}' -f $privacyConsent)
Write-Host ('  Windows Hello provisioned       : {0}  (unlock factor for Windows passkeys)' -f $ds['NgcSet'])
Write-Host ('  Bluetooth service (cross-device): {0}' -f $(if ($btService) { $btService.Status } else { 'not present' }))
Write-Host '  ------------------------------------------------------------'
if ($privacyConsent) {
    Write-Host '  This device has the 24H2 passkey-access controls' -ForegroundColor Green
    Write-Host '  (Settings > Privacy & security > Passkey access).' -ForegroundColor Green
} elseif ($nativeMgmt) {
    Write-Host '  Native passkey management is available; upgrade to 24H2 for per-app' -ForegroundColor Yellow
    Write-Host '  passkey privacy consent controls.' -ForegroundColor Yellow
} else {
    Write-Host '  Passkeys can still be used, but native management arrived in 22H2.' -ForegroundColor Yellow
}
if ($ds['NgcSet'] -ne 'YES') {
    Write-Host '  Note: no Windows Hello credential - set up Hello to unlock Windows passkeys.' -ForegroundColor Gray
}
Write-Host ''
