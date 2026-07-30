<#
.SYNOPSIS
    Checks whether a device is ready to use Windows Hello for Business (WHfB)
    for Remote Desktop (RDP) sign-in, via either the certificate-based
    redirected-smart-card approach or Remote Credential Guard.

.DESCRIPTION
    Windows Hello for Business cannot be used directly to authenticate a
    Remote Desktop session - the TPM-sealed WHfB key never leaves the local
    device. Microsoft documents two supported workarounds instead:
      1. Deploy a certificate into the WHfB container that Windows can present
         as a redirected smart card credential.
      2. Use Remote Credential Guard, which uses Kerberos to give the remote
         session single sign-on without ever transmitting credential material -
         but only works when the target device is joined to an on-premises
         Active Directory domain, not when the target is Microsoft Entra
         joined only.

    This script checks, on the local device:
      - Whether Windows Hello for Business is actually provisioned
        (dsregcmd /status, NgcSet)
      - Whether a certificate suitable for redirected-smart-card RDP sign-in
        exists in the WHfB container (Provider = Microsoft Passport Key
        Storage Provider, with the Smart Card Logon and Client Authentication
        Extended Key Usages)
      - What the local Remote Credential Guard client policy currently allows

    This script is strictly read-only. It makes no changes to certificates,
    registry values, or policy of any kind.

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-hello-for-business-remote-desktop-rdp-sign-in.html
    Author:    Imran Awan
    Version:   1.0

    Known gaps flagged rather than guessed at:
    - Microsoft's own documentation only publishes the registry mapping for
      the REMOTE HOST side of the Remote Credential Guard policy
      (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin). The
      exact registry path the CLIENT-side "Restrict delegation of credentials
      to remote servers" policy writes to is not published by Microsoft in
      this exact form. This script reads the commonly observed location
      (HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation) and
      reports it as an indicator only - always confirm authoritatively with
      gpresult /h if this matters for a compliance decision.

.EXAMPLE
    .\Test-WHfBRdpReadiness.ps1
    Runs all three checks on the local device and prints a summary.
#>

[CmdletBinding()]
param ()

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

$results = [ordered]@{
    WHfBProvisioned         = $false
    RdpCertificateFound     = $false
    RemoteCredentialGuardOn = $false
}

#region 1. WHfB provisioning state
Write-Section "Windows Hello for Business provisioning"

try {
    $dsreg = & dsregcmd.exe /status 2>&1
} catch {
    Write-Host "  [FAIL] Could not run dsregcmd.exe: $($_.Exception.Message)" -ForegroundColor Red
    $dsreg = @()
}

$ngcLine = $dsreg | Where-Object { $_ -match 'NgcSet\s*:' }
if ($ngcLine -and $ngcLine -match 'YES') {
    Write-Host "  [OK  ] NGC key present for current user (dsregcmd /status: $($ngcLine.Trim()))" -ForegroundColor Green
    $results.WHfBProvisioned = $true
} elseif ($ngcLine) {
    Write-Host "  [WARN] Windows Hello for Business is NOT provisioned for this user ($($ngcLine.Trim()))" -ForegroundColor Yellow
} else {
    Write-Host "  [WARN] Could not determine NgcSet state from dsregcmd /status output." -ForegroundColor Yellow
}
#endregion

#region 2. Redirected smart card certificate in the WHfB container
Write-Section "Redirected smart card certificate (WHfB container)"

$smartCardLogonEku = '1.3.6.1.4.1.311.20.2.2'
$clientAuthEku     = '1.3.6.1.5.5.7.3.2'

try {
    $certs = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop
} catch {
    Write-Host "  [FAIL] Could not read the current user's certificate store: $($_.Exception.Message)" -ForegroundColor Red
    $certs = @()
}

$candidateCerts = foreach ($cert in $certs) {
    $ekuOids = $cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }
    $hasSmartCardLogon = $ekuOids -contains $smartCardLogonEku
    $hasClientAuth     = $ekuOids -contains $clientAuthEku

    $providerName = $null
    try {
        if ($cert.PrivateKey -and $cert.PrivateKey.CspKeyContainerInfo) {
            $providerName = $cert.PrivateKey.CspKeyContainerInfo.ProviderName
        } elseif ($cert.HasPrivateKey) {
            # CNG-backed keys (WHfB certs are CNG, not legacy CAPI) do not expose
            # CspKeyContainerInfo the same way - fall back to certutil for the
            # authoritative provider name rather than guessing.
            $providerName = 'Unknown (CNG key - see certutil output below for the authoritative provider)'
        }
    } catch {
        $providerName = 'Unknown (unable to read private key provider)'
    }

    if ($hasSmartCardLogon -and $hasClientAuth) {
        [PSCustomObject]@{
            Subject      = $cert.Subject
            Thumbprint   = $cert.Thumbprint
            NotAfter     = $cert.NotAfter
            DaysToExpiry = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
            Provider     = $providerName
        }
    }
}

if ($candidateCerts) {
    foreach ($c in $candidateCerts) {
        Write-Host "  [OK  ] Certificate found: $($c.Subject)" -ForegroundColor Green
        Write-Host "  [OK  ]   Provider: $($c.Provider)" -ForegroundColor Green
        Write-Host "  [OK  ]   EKU: Smart Card Logon, Client Authentication" -ForegroundColor Green
        Write-Host "  [OK  ]   Expires: $($c.NotAfter.ToString('yyyy-MM-dd')) ($($c.DaysToExpiry) day(s) remaining)" -ForegroundColor Green
    }
    Write-Host "  [RESULT] This device CAN use certificate-based WHfB sign-in for RDP." -ForegroundColor Cyan
    $results.RdpCertificateFound = $true
} else {
    Write-Host "  [WARN] No certificate with both Smart Card Logon and Client Authentication EKUs was found." -ForegroundColor Yellow
    Write-Host "  [RESULT] This device CANNOT currently use certificate-based WHfB sign-in for RDP." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  For the authoritative Key Storage Provider name, cross-check with:" -ForegroundColor Gray
Write-Host "    certutil -store -user my" -ForegroundColor Gray
Write-Host "  Look for 'Provider = Microsoft Passport Key Storage Provider' on the certificate above." -ForegroundColor Gray
#endregion

#region 3. Remote Credential Guard client policy
Write-Section "Remote Credential Guard (client policy)"

$rcgRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
$rcgValueName = 'RestrictedRemoteAdministration'

$rcgState = 'NOT CONFIGURED'
try {
    if (Test-Path $rcgRegPath) {
        $rcgValue = Get-ItemProperty -Path $rcgRegPath -Name $rcgValueName -ErrorAction SilentlyContinue
        if ($null -ne $rcgValue.$rcgValueName) {
            switch ($rcgValue.$rcgValueName) {
                0 { $rcgState = 'Disabled' }
                1 { $rcgState = 'Require Restricted Admin' }
                2 { $rcgState = 'Require Remote Credential Guard' }
                3 { $rcgState = 'Restrict credential delegation (RCG preferred, falls back to Restricted Admin)' }
                default { $rcgState = "Unrecognised value: $($rcgValue.$rcgValueName)" }
            }
        }
    }
} catch {
    Write-Host "  [WARN] Could not read Remote Credential Guard policy from the registry: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "  [INFO ] RestrictedRemoteAdministration policy: $rcgState" -ForegroundColor Cyan

if ($rcgState -eq 'Require Remote Credential Guard' -or $rcgState -like 'Restrict credential delegation*') {
    Write-Host "  [OK  ] This device is enforcing Remote Credential Guard (or an equivalent) by policy." -ForegroundColor Green
    $results.RemoteCredentialGuardOn = $true
} else {
    Write-Host "  [WARN] No client policy found requiring Remote Credential Guard." -ForegroundColor Yellow
    Write-Host "  [INFO ]   Use 'mstsc.exe /remoteGuard' for a one-off connection, or" -ForegroundColor Gray
    Write-Host "  [INFO ]   configure the client policy for fleet-wide enforcement (see blog post)." -ForegroundColor Gray
    Write-Host "  [RESULT] This device is NOT currently enforcing Remote Credential Guard by policy." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  Remote Credential Guard only works when the RDP TARGET is joined to an" -ForegroundColor Gray
Write-Host "  on-premises Active Directory domain. It cannot be used against a target" -ForegroundColor Gray
Write-Host "  that is Microsoft Entra joined only." -ForegroundColor Gray
Write-Host ""
Write-Host "  This check is a helpful indicator only - Microsoft does not publish an" -ForegroundColor Gray
Write-Host "  official registry mapping for this specific client-side policy. Confirm" -ForegroundColor Gray
Write-Host "  authoritatively with: gpresult /h report.html" -ForegroundColor Gray
#endregion

#region Summary
Write-Section "Summary"
Write-Host ("Certificate-based RDP sign-in : {0}" -f $(if ($results.RdpCertificateFound) { 'READY' } else { 'NOT READY' }))
Write-Host ("Remote Credential Guard       : {0}" -f $(if ($results.RemoteCredentialGuardOn) { 'ENFORCED BY POLICY' } else { 'NOT ENFORCED (policy not configured)' }))
Write-Host ""
Write-Host "This script performed read-only checks only. No settings were changed." -ForegroundColor DarkGray

return [PSCustomObject]$results
#endregion
