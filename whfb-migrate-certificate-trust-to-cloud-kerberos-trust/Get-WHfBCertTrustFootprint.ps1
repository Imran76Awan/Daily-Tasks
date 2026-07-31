<#
.SYNOPSIS
    Read-only report of a device's Windows Hello for Business certificate-trust
    footprint and its readiness to move to cloud Kerberos trust.

.DESCRIPTION
    Changes nothing. For the signed-in user it reports:

      1. Whether a WHfB logon certificate exists (private key in the
         'Microsoft Passport Key Storage Provider' = a Hello cert).
      2. The UseCertificateForOnPremAuth policy value (1 = pinned to cert trust).
      3. The UseCloudTrustForOnPremAuth policy value (1 = cloud trust configured).
      4. Join / PRT / TGT state from dsregcmd.

    It then prints a one-line verdict telling you which migration action the
    device still needs:  PIN container delete, policy change, or already migrated.

    Run it across a pilot ring (as the logged-on user) to see which devices are
    still carrying a certificate-trust credential.

.PARAMETER AsObject
    Return a PSCustomObject instead of the console report (pipe to Export-Csv).

.EXAMPLE
    .\Get-WHfBCertTrustFootprint.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-migrate-certificate-trust-to-cloud-kerberos-trust.html
    Safe   : READ-ONLY. Does not delete the Hello container or change policy.
    Run as : The signed-in user (so it reads that user's certificate store).
#>

[CmdletBinding()]
param([switch]$AsObject)

# ---- 1. WHfB certificate-trust LOGON certificate ---------------------------
# A real cert-trust logon cert is: key in the Microsoft Passport KSP, carries a
# Smart Card Logon (1.3.6.1.4.1.311.20.2.2) or Client Authentication
# (1.3.6.1.5.5.7.3.2) EKU, AND is issued by an enterprise CA (Issuer != Subject).
# That last test is what excludes the self-issued Entra device-registration
# certificate, which also lives in the Passport KSP but is NOT a WHfB logon cert.
$SCLOGON  = '1.3.6.1.4.1.311.20.2.2'
$CLIENTAUTH = '1.3.6.1.5.5.7.3.2'
$helloCert = $null
foreach ($c in (Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)) {
    if ($c.Issuer -eq $c.Subject) { continue }   # self-issued = device cert, skip
    $ekuOids = @()
    foreach ($ext in $c.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $ekuOids += $ext.EnhancedKeyUsages.Value
        }
    }
    if (-not ($ekuOids -contains $SCLOGON -or $ekuOids -contains $CLIENTAUTH)) { continue }
    $providerIsPassport = $false
    try {
        if ((certutil -store -user My $c.Thumbprint 2>$null) | Select-String -Pattern 'Passport' -Quiet) {
            $providerIsPassport = $true
        }
    } catch { }
    if ($providerIsPassport) { $helloCert = $c; break }
}

# ---- 2 & 3. PassportForWork policy values ----------------------------------
$useCert  = $null
$useCloud = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.UseCertificateForOnPremAuth) { $useCert  = $v.UseCertificateForOnPremAuth }
            if ($null -ne $v.UseCloudTrustForOnPremAuth)   { $useCloud = $v.UseCloudTrustForOnPremAuth }
        }
    }
}

# ---- 4. dsregcmd state -----------------------------------------------------
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

# ---- Verdict ---------------------------------------------------------------
$verdict =
    if ($helloCert -and $useCert -eq 1) {
        'ON CERT TRUST - needs policy change + certutil -deletehellocontainer'
    } elseif ($helloCert) {
        'Has a WHfB cert but cert policy not pinned - delete container to drop it'
    } elseif ($useCloud -eq 1 -and $ds['OnPremTgt'] -eq 'YES') {
        'MIGRATED - on cloud Kerberos trust (OnPremTgt=YES, no WHfB cert)'
    } elseif ($useCloud -eq 1) {
        'Cloud-trust policy set, no WHfB cert - awaiting first DC sign-in'
    } else {
        'No WHfB cert and no cloud-trust policy - review configuration'
    }

$out = [PSCustomObject]@{
    WHfBCertificate = if ($helloCert) { "$($helloCert.Subject) (exp $($helloCert.NotAfter.ToString('yyyy-MM-dd')))" } else { 'none' }
    UseCertForOnPrem = if ($null -ne $useCert)  { $useCert }  else { 'not set' }
    UseCloudTrust    = if ($null -ne $useCloud) { $useCloud } else { 'not set' }
    AzureAdJoined    = $ds['AzureAdJoined']
    OnPremTgt        = $ds['OnPremTgt']
    Verdict          = $verdict
}

if ($AsObject) { return $out }

Write-Host ''
Write-Host '  WHfB Certificate-Trust Footprint' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  WHfB certificate     : {0}' -f $out.WHfBCertificate)
Write-Host ('  UseCertForOnPrem     : {0}' -f $out.UseCertForOnPrem)
Write-Host ('  UseCloudTrust        : {0}' -f $out.UseCloudTrust)
Write-Host ('  AzureAdJoined        : {0}' -f $out.AzureAdJoined)
Write-Host ('  OnPremTgt            : {0}' -f $out.OnPremTgt)
Write-Host '  ------------------------------------------------------------'
$vColor = if ($verdict -like 'MIGRATED*') { 'Green' } elseif ($verdict -like 'ON CERT TRUST*') { 'Yellow' } else { 'Gray' }
Write-Host ('  {0}' -f $verdict) -ForegroundColor $vColor
Write-Host ''
