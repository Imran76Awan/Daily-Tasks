<#
.SYNOPSIS
    Read-only check of whether non-destructive Windows Hello for Business PIN
    reset is live on this device.

.DESCRIPTION
    Changes nothing. Reports:
      1. dsregcmd 'CanReset' - DestructiveOnly vs DestructiveAndNonDestructive.
      2. The EnablePinRecovery PassportForWork policy value in the registry.
      3. NgcSet / NgcKeyId for context.

    Verdict maps to what the user will experience if they forget their PIN.

.PARAMETER AsObject
    Return a PSCustomObject instead of the console report.

.EXAMPLE
    .\Get-PinResetReadiness.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-pin-reset-destructive-nondestructive.html
    Safe   : READ-ONLY.
    Run as : The signed-in user.
#>

[CmdletBinding()]
param([switch]$AsObject)

# dsregcmd user state
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

# EnablePinRecovery policy
$enablePinRecovery = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.EnablePinRecovery) { $enablePinRecovery = $v.EnablePinRecovery }
        }
    }
}

$canReset = $ds['CanReset']
$verdict =
    if ($canReset -eq 'DestructiveAndNonDestructive') {
        'NON-DESTRUCTIVE reset is LIVE - forgotten PIN keeps the credential.'
    } elseif ($canReset -eq 'DestructiveOnly') {
        'DESTRUCTIVE only - a forgotten PIN re-enrols the credential (risky on hybrid key trust).'
    } else {
        'CanReset not reported - is a Hello credential provisioned for this user?'
    }

$out = [PSCustomObject]@{
    CanReset          = $canReset
    EnablePinRecovery = if ($null -ne $enablePinRecovery) { $enablePinRecovery } else { 'not set' }
    NgcSet            = $ds['NgcSet']
    NgcKeyId          = $ds['NgcKeyId']
    Verdict           = $verdict
}
if ($AsObject) { return $out }

Write-Host ''
Write-Host '  WHfB PIN Reset Readiness' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  CanReset (dsregcmd)   : {0}' -f $out.CanReset)
Write-Host ('  EnablePinRecovery pol : {0}' -f $out.EnablePinRecovery)
Write-Host ('  NgcSet                : {0}' -f $out.NgcSet)
Write-Host '  ------------------------------------------------------------'
$c = if ($canReset -eq 'DestructiveAndNonDestructive') { 'Green' } elseif ($canReset -eq 'DestructiveOnly') { 'Yellow' } else { 'Gray' }
Write-Host ('  {0}' -f $verdict) -ForegroundColor $c
Write-Host ''
