<#
.SYNOPSIS
    Read-only readiness check for Windows Hello for Business dual enrollment.

.DESCRIPTION
    Changes nothing. Dual enrollment is niche: it requires certificate trust,
    domain or Entra hybrid join, and the Group Policy-only setting "Allow
    enumeration of emulated smart cards for all users". This script reports each
    of those so you know whether a device can actually support dual enrollment.

    Checks:
      1. Join type from dsregcmd (domain/hybrid required).
      2. The enumeration GPO value in the registry (AllowEnumerationOfEmulatedSmartCards).
      3. A certificate-trust heuristic: a WHfB logon cert (Passport KSP + Smart Card
         Logon EKU issued by an enterprise CA), plus UseCertificateForOnPremAuth.

.EXAMPLE
    .\Get-DualEnrollmentReadiness.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-dual-enrollment-privileged-admin.html
    Safe   : READ-ONLY.
    Run as : The signed-in user (to read the user certificate store).
#>

[CmdletBinding()]
param()

# 1. Join type
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}
$joinOk = ($ds['DomainJoined'] -eq 'YES')   # domain or hybrid both show DomainJoined=YES

# 2. Enumeration GPO value + cert-trust policy
$enumAllowed = $null; $useCert = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            foreach ($p in $v.PSObject.Properties) {
                if ($p.Name -match 'EnumerationOfEmulatedSmartCard|AllowEnumeration') { $enumAllowed = $p.Value }
            }
            if ($null -ne $v.UseCertificateForOnPremAuth) { $useCert = $v.UseCertificateForOnPremAuth }
        }
    }
}

# 3. Cert-trust logon cert heuristic
$SCLOGON = '1.3.6.1.4.1.311.20.2.2'
$hasHelloCert = $false
foreach ($c in (Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)) {
    if ($c.Issuer -eq $c.Subject) { continue }
    $ekus = @()
    foreach ($ext in $c.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) { $ekus += $ext.EnhancedKeyUsages.Value }
    }
    if ($ekus -contains $SCLOGON) {
        try { if ((certutil -store -user My $c.Thumbprint 2>$null) | Select-String 'Passport' -Quiet) { $hasHelloCert = $true; break } } catch { }
    }
}
$certTrust = ($useCert -eq 1) -or $hasHelloCert

Write-Host ''
Write-Host '  WHfB Dual Enrollment - Readiness' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Domain/hybrid joined            : {0}' -f $(if ($joinOk) { 'YES' } else { 'NO (required)' }))
Write-Host ('  Certificate trust (heuristic)   : {0}' -f $(if ($certTrust) { 'YES' } else { 'NO / not detected (REQUIRED - not key or cloud trust)' }))
Write-Host ('  Enumeration GPO enabled         : {0}' -f $(if ($enumAllowed -eq 1) { 'YES' } elseif ($null -ne $enumAllowed) { $enumAllowed } else { 'not set (GPO-only; cannot come from Intune)' }))
Write-Host '  ------------------------------------------------------------'
if ($joinOk -and $certTrust -and $enumAllowed -eq 1) {
    Write-Host '  READY: device meets the dual-enrollment prerequisites.' -ForegroundColor Green
} elseif (-not $certTrust) {
    Write-Host '  NOT READY: dual enrollment requires certificate trust. Key trust and' -ForegroundColor Yellow
    Write-Host '  cloud Kerberos trust are not supported.' -ForegroundColor Yellow
} else {
    Write-Host '  NOT READY: enable the enumeration GPO and confirm cert trust + join type.' -ForegroundColor Yellow
}
Write-Host ''
