<#
.SYNOPSIS
    Read-only readiness check for Windows Hello for Business (WHfB) cloud Kerberos trust.

.DESCRIPTION
    Runs entirely locally and changes nothing. It inspects the five things that
    decide whether a device can use WHfB cloud Kerberos trust and reports a
    PASS / WARN / FAIL for each, plus an overall verdict:

      1. Device join state          (dsregcmd /status : AzureAdJoined / DomainJoined)
      2. Primary Refresh Token       (dsregcmd /status : AzureAdPrt)
      3. On-prem / cloud TGT state   (dsregcmd /status : OnPremTgt / CloudTgt)
      4. TPM presence and readiness  (Get-Tpm)
      5. WHfB + cloud-trust policy    (PassportForWork policy registry keys)

    It also runs 'klist' and reports whether a full krbtgt ticket is cached,
    which is the real proof that the partial-to-full TGT exchange succeeded.

    Use it before enabling cloud Kerberos trust (to confirm prerequisites) and
    after enrolment (to confirm success).

.PARAMETER AsObject
    Return the results as a PSCustomObject instead of writing the formatted
    console report. Useful for piping into Export-Csv or an Intune remediation.

.EXAMPLE
    .\Test-CloudKerberosTrustReadiness.ps1

.EXAMPLE
    .\Test-CloudKerberosTrustReadiness.ps1 -AsObject | Export-Csv .\readiness.csv -NoTypeInformation

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-cloud-kerberos-trust-deployment-guide.html
    Safe   : READ-ONLY. No policy, registry, or credential state is modified.
    Run as : Standard user is fine; run as the signed-in user to read that user's TGT/PRT.
#>

[CmdletBinding()]
param(
    [switch]$AsObject
)

function Get-DsRegStatus {
    # Parse 'dsregcmd /status' into a hashtable of Key = Value pairs.
    $raw = & dsregcmd /status 2>$null
    $map = @{}
    foreach ($line in $raw) {
        if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') {
            $map[$Matches[1]] = $Matches[2].Trim()
        }
    }
    return $map
}

function New-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    [PSCustomObject]@{ Check = $Name; Status = $Status; Detail = $Detail }
}

$results = New-Object System.Collections.Generic.List[object]

# ---- 1..3  dsregcmd-derived checks -----------------------------------------
$ds = Get-DsRegStatus

$aadJoined = $ds['AzureAdJoined']
$domJoined = $ds['DomainJoined']
if ($aadJoined -eq 'YES') {
    $results.Add((New-Check 'Entra join state' 'PASS' "AzureAdJoined=YES, DomainJoined=$domJoined"))
} else {
    $results.Add((New-Check 'Entra join state' 'FAIL' "AzureAdJoined=$aadJoined - no PRT means no partial TGT"))
}

$prt = $ds['AzureAdPrt']
if ($prt -eq 'YES') {
    $results.Add((New-Check 'Primary Refresh Token' 'PASS' 'AzureAdPrt=YES'))
} else {
    $results.Add((New-Check 'Primary Refresh Token' 'FAIL' "AzureAdPrt=$prt - cloud trust cannot issue a ticket without a PRT"))
}

$onPremTgt = $ds['OnPremTgt']
$cloudTgt  = $ds['CloudTgt']
if ($onPremTgt -eq 'YES') {
    $results.Add((New-Check 'On-prem TGT (post-enrolment)' 'PASS' "OnPremTgt=YES, CloudTgt=$cloudTgt"))
} elseif ($domJoined -eq 'YES') {
    $results.Add((New-Check 'On-prem TGT (post-enrolment)' 'WARN' "OnPremTgt=$onPremTgt - expected before first DC sign-in; FAIL only if already enrolled"))
} else {
    $results.Add((New-Check 'On-prem TGT (post-enrolment)' 'WARN' 'Entra-only device - on-prem TGT not applicable'))
}

# ---- 4  TPM ----------------------------------------------------------------
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        $results.Add((New-Check 'TPM' 'PASS' 'TpmPresent=True, TpmReady=True'))
    } elseif ($tpm.TpmPresent) {
        $results.Add((New-Check 'TPM' 'WARN' "TpmPresent=True but TpmReady=$($tpm.TpmReady)"))
    } else {
        $results.Add((New-Check 'TPM' 'WARN' 'No TPM - WHfB will fall back to software keys unless RequireSecurityDevice blocks it'))
    }
} catch {
    $results.Add((New-Check 'TPM' 'WARN' "Get-Tpm unavailable: $($_.Exception.Message)"))
}

# ---- 5  WHfB + cloud-trust policy in the registry --------------------------
# The PassportForWork CSP lands policy under one of these roots, per tenant GUID.
$policyRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
)
$usePassport = $null
$useCloudTrust = $null
foreach ($root in $policyRoots) {
    if (Test-Path $root) {
        # Walk to any *\Device\Policies or *\Policies subkey and read the values.
        Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $vals = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $vals.UsePassportForWork)        { $usePassport   = $vals.UsePassportForWork }
            if ($null -ne $vals.UseCloudTrustForOnPremAuth) { $useCloudTrust = $vals.UseCloudTrustForOnPremAuth }
        }
    }
}
if ($usePassport -eq 1 -and $useCloudTrust -eq 1) {
    $results.Add((New-Check 'WHfB cloud-trust policy' 'PASS' 'UsePassportForWork=1 and UseCloudTrustForOnPremAuth=1'))
} elseif ($usePassport -eq 1) {
    $results.Add((New-Check 'WHfB cloud-trust policy' 'WARN' "UsePassportForWork=1 but UseCloudTrustForOnPremAuth=$useCloudTrust"))
} else {
    $results.Add((New-Check 'WHfB cloud-trust policy' 'WARN' 'No PassportForWork policy found in registry yet (policy may not have synced)'))
}

# ---- klist proof -----------------------------------------------------------
$klist = & klist 2>$null
$hasFullTgt = ($klist | Select-String -Pattern 'krbtgt/' -Quiet)
if ($hasFullTgt) {
    $results.Add((New-Check 'Cached full TGT (klist)' 'PASS' 'krbtgt ticket present - partial-to-full exchange succeeded'))
} else {
    $results.Add((New-Check 'Cached full TGT (klist)' 'WARN' 'No krbtgt ticket cached (expected on Entra-only or before first DC sign-in)'))
}

# ---- Output ----------------------------------------------------------------
if ($AsObject) {
    $results
    return
}

$overall = if ($results.Status -contains 'FAIL') { 'NOT READY' }
           elseif ($results.Status -contains 'WARN') { 'READY WITH WARNINGS' }
           else { 'READY' }

Write-Host ''
Write-Host '  WHfB Cloud Kerberos Trust - Readiness Check' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
foreach ($r in $results) {
    $color = switch ($r.Status) { 'PASS' {'Green'} 'WARN' {'Yellow'} default {'Red'} }
    Write-Host ('  [{0,-4}] {1,-30} {2}' -f $r.Status, $r.Check, $r.Detail) -ForegroundColor $color
}
Write-Host '  ------------------------------------------------------------'
$oColor = switch ($overall) { 'READY' {'Green'} 'READY WITH WARNINGS' {'Yellow'} default {'Red'} }
Write-Host ('  OVERALL: {0}' -f $overall) -ForegroundColor $oColor
Write-Host ''
