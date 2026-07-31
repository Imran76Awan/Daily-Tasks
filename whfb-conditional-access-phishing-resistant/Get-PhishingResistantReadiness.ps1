<#
.SYNOPSIS
    Read-only check of whether this device can satisfy the built-in
    Phishing-resistant MFA authentication strength via Windows Hello for Business.

.DESCRIPTION
    Changes nothing and needs no tenant connection. Reports whether a WHfB
    credential exists and is hardware-backed (the two things that make WHfB a
    strong phishing-resistant method on this device), and prints the built-in
    authentication-strength method reference so you can see what each strength
    accepts. It does NOT query Conditional Access policies (that needs Graph).

.EXAMPLE
    .\Get-PhishingResistantReadiness.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-conditional-access-phishing-resistant.html
    Safe   : READ-ONLY, offline.
    Run as : The signed-in user.
#>

[CmdletBinding()]
param()

$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}
$helloPresent = ($ds['NgcSet'] -eq 'YES')

$tpmReady = $false
try { $t = Get-Tpm -ErrorAction Stop; $tpmReady = ($t.TpmPresent -and $t.TpmReady) } catch { }

Write-Host ''
Write-Host '  Phishing-Resistant Readiness (via WHfB)' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  WHfB credential present (NgcSet) : {0}' -f $ds['NgcSet'])
Write-Host ('  TPM present and ready            : {0}' -f $tpmReady)
Write-Host '  ------------------------------------------------------------'
if ($helloPresent -and $tpmReady) {
    Write-Host '  READY: this device has a hardware-backed WHfB credential and can satisfy' -ForegroundColor Green
    Write-Host '  the built-in Phishing-resistant MFA authentication strength.' -ForegroundColor Green
} elseif ($helloPresent) {
    Write-Host '  WHfB present but not confirmed TPM-backed - still counts as WHfB, but' -ForegroundColor Yellow
    Write-Host '  require a hardware security device for the strongest guarantee.' -ForegroundColor Yellow
} else {
    Write-Host '  NOT READY: no WHfB credential on this device. The user would need WHfB,' -ForegroundColor Yellow
    Write-Host '  a FIDO2 key, or multifactor certificate-based auth to meet the strength.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Built-in strength reference (methods that satisfy each):' -ForegroundColor Cyan
Write-Host '    Method                                  MFA  Passwordless  Phishing-resistant'
Write-Host '    FIDO2 security key                       X       X              X'
Write-Host '    Windows Hello for Business               X       X              X'
Write-Host '    Certificate-based auth (multifactor)     X       X              X'
Write-Host '    Microsoft Authenticator (phone sign-in)  X       X'
Write-Host '    Temporary Access Pass                    X'
Write-Host '    Password + something the user has        X'
Write-Host ''
