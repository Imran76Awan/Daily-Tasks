<#
.SYNOPSIS
    Read-only detector that reports which Windows Hello for Business trust model
    a device is actually using: certificate trust, key trust, or cloud Kerberos trust.

.DESCRIPTION
    Changes nothing. It reads three signals and reasons over them:

      1. WHfB logon certificate in the user store
         (Passport KSP + Smart Card Logon EKU + issued by an enterprise CA).
      2. PassportForWork policy values UsePassportForWork / UseCertificateForOnPremAuth
         / UseCloudTrustForOnPremAuth.
      3. Device join, PRT and TGT state from dsregcmd.

    Detection logic:
      - WHfB cert present + UseCertificateForOnPremAuth=1  -> CERTIFICATE TRUST
      - UseCloudTrustForOnPremAuth=1                       -> CLOUD KERBEROS TRUST
      - UsePassportForWork=1, no cert, no cloud policy      -> KEY TRUST (likely)
      - none of the above                                  -> WHfB not configured

    Key trust and cloud trust look nearly identical on the client, so the cloud
    policy value is treated as the tiebreaker (see the blog post).

.PARAMETER AsObject
    Return a PSCustomObject instead of the console report.

.EXAMPLE
    .\Get-WHfBTrustModel.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-key-trust-vs-cert-trust-vs-cloud-kerberos-trust.html
    Safe   : READ-ONLY.
    Run as : The signed-in user.
#>

[CmdletBinding()]
param([switch]$AsObject)

$SCLOGON = '1.3.6.1.4.1.311.20.2.2'
$CLIENTAUTH = '1.3.6.1.5.5.7.3.2'

# ---- WHfB logon certificate ------------------------------------------------
$hasHelloCert = $false
foreach ($c in (Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)) {
    if ($c.Issuer -eq $c.Subject) { continue }
    $ekus = @()
    foreach ($ext in $c.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $ekus += $ext.EnhancedKeyUsages.Value
        }
    }
    if (-not ($ekus -contains $SCLOGON -or $ekus -contains $CLIENTAUTH)) { continue }
    try {
        if ((certutil -store -user My $c.Thumbprint 2>$null) | Select-String 'Passport' -Quiet) { $hasHelloCert = $true; break }
    } catch { }
}

# ---- PassportForWork policy ------------------------------------------------
$usePassport = $null; $useCert = $null; $useCloud = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.UsePassportForWork)         { $usePassport = $v.UsePassportForWork }
            if ($null -ne $v.UseCertificateForOnPremAuth) { $useCert     = $v.UseCertificateForOnPremAuth }
            if ($null -ne $v.UseCloudTrustForOnPremAuth)  { $useCloud    = $v.UseCloudTrustForOnPremAuth }
        }
    }
}

# ---- dsregcmd --------------------------------------------------------------
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

# ---- Decide ----------------------------------------------------------------
$model =
    if     ($hasHelloCert -and $useCert -eq 1) { 'CERTIFICATE TRUST' }
    elseif ($hasHelloCert)                     { 'CERTIFICATE TRUST (cert present; policy not pinned)' }
    elseif ($useCloud -eq 1)                   { 'CLOUD KERBEROS TRUST' }
    elseif ($usePassport -eq 1)                { 'KEY TRUST (likely - no cert, no cloud policy)' }
    else                                       { 'WHfB not configured / not detectable from client' }

$out = [PSCustomObject]@{
    TrustModel                 = $model
    WHfBLogonCert              = $hasHelloCert
    UsePassportForWork         = if ($null -ne $usePassport) { $usePassport } else { 'not set' }
    UseCertificateForOnPrem    = if ($null -ne $useCert)     { $useCert }     else { 'not set' }
    UseCloudTrustForOnPrem     = if ($null -ne $useCloud)    { $useCloud }    else { 'not set' }
    AzureAdJoined              = $ds['AzureAdJoined']
    DomainJoined               = $ds['DomainJoined']
    OnPremTgt                  = $ds['OnPremTgt']
}

if ($AsObject) { return $out }

Write-Host ''
Write-Host '  WHfB Trust Model Detector' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  WHfB logon cert        : {0}' -f $out.WHfBLogonCert)
Write-Host ('  UsePassportForWork     : {0}' -f $out.UsePassportForWork)
Write-Host ('  UseCertForOnPrem       : {0}' -f $out.UseCertificateForOnPrem)
Write-Host ('  UseCloudTrust          : {0}' -f $out.UseCloudTrustForOnPrem)
Write-Host ('  Join (AAD/Domain)      : {0} / {1}' -f $out.AzureAdJoined, $out.DomainJoined)
Write-Host ('  OnPremTgt              : {0}' -f $out.OnPremTgt)
Write-Host '  ------------------------------------------------------------'
Write-Host ('  DETECTED MODEL: {0}' -f $model) -ForegroundColor Green
Write-Host ''
