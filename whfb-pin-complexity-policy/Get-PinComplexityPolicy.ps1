<#
.SYNOPSIS
    Read-only report of the applied Windows Hello for Business PIN complexity
    policy, and whether PIN expiration/history will actually enforce on this device.

.DESCRIPTION
    Changes nothing. Reads every PINComplexity value applied under the
    PassportForWork policy tree and prints the effective PIN rules. It also checks
    Virtualization-based Security (VBS) status and the OS build, because PIN
    expiration and history are NOT enforced on ESS devices or, from Windows 11
    24H2 onward, on any device with VBS enabled - so it flags when those two
    settings are a silent no-op.

.EXAMPLE
    .\Get-PinComplexityPolicy.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-pin-complexity-policy.html
    Safe   : READ-ONLY.
#>

[CmdletBinding()]
param()

$fields = 'MinimumPINLength','MaximumPINLength','Digits','LowercaseLetters',
          'UppercaseLetters','SpecialCharacters','Expiration','History'
$vals = @{}
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -eq 'PINComplexity' } | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                foreach ($f in $fields) { if ($null -ne $p.$f) { $vals[$f] = $p.$f } }
            }
    }
}

# VBS status + OS build for the expiration/history caveat
$vbsRunning = $false
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbsRunning = ($dg.VirtualizationBasedSecurityStatus -eq 2)
} catch { }
$build = [int]([System.Environment]::OSVersion.Version.Build)
$is24H2OrLater = ($build -ge 26100)

$stateWord = { param($v) if ($null -eq $v) { 'not set' } elseif ($v -eq 1) { 'REQUIRE' } elseif ($v -eq 2) { 'do not allow' } else { $v } }

Write-Host ''
Write-Host '  WHfB PIN Complexity - Effective Policy' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Minimum PIN length   : {0}' -f $(if ($null -ne $vals.MinimumPINLength) { $vals.MinimumPINLength } else { 'not set (default 6)' }))
Write-Host ('  Maximum PIN length   : {0}' -f $(if ($null -ne $vals.MaximumPINLength) { $vals.MaximumPINLength } else { 'not set (default 127)' }))
Write-Host ('  Digits               : {0}' -f (& $stateWord $vals.Digits))
Write-Host ('  Lowercase letters    : {0}' -f (& $stateWord $vals.LowercaseLetters))
Write-Host ('  Uppercase letters    : {0}' -f (& $stateWord $vals.UppercaseLetters))
Write-Host ('  Special characters   : {0}' -f (& $stateWord $vals.SpecialCharacters))
Write-Host ('  Expiration (days)    : {0}' -f $(if ($null -ne $vals.Expiration) { $vals.Expiration } else { 'not set (0 = never)' }))
Write-Host ('  History (remembered) : {0}' -f $(if ($null -ne $vals.History) { $vals.History } else { 'not set (0)' }))
Write-Host '  ------------------------------------------------------------'
Write-Host ('  OS build: {0}   VBS running: {1}' -f $build, $vbsRunning)
if (($vbsRunning -or $is24H2OrLater) -and (($vals.Expiration -and $vals.Expiration -ne 0) -or ($vals.History -and $vals.History -ne 0))) {
    Write-Host '  WARNING: PIN Expiration/History are configured but will NOT enforce on this' -ForegroundColor Yellow
    Write-Host '  device (VBS enabled / Windows 11 24H2+). Treat them as a no-op here.' -ForegroundColor Yellow
} elseif ($vbsRunning -or $is24H2OrLater) {
    Write-Host '  Note: PIN Expiration/History would not enforce here (VBS / 24H2+) - none set, so fine.' -ForegroundColor Gray
} else {
    Write-Host '  PIN complexity read successfully.' -ForegroundColor Green
}
Write-Host ''
