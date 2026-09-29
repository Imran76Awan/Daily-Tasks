<#
.SYNOPSIS
    Intune Proactive Remediation DETECTION script. Reports whether Windows Hello for
    Business policy was actually delivered to the device and whether Hello is provisioned.

.DESCRIPTION
    Detection-only. There is deliberately no matching remediation script for this check,
    and that is not an oversight:

      - WHfB policy is owned by the MDM channel. Writing those registry values locally
        would be overwritten on the next sync, and would hide the real problem.
      - If policy is missing, the fix is in Intune (assignment, filter, licensing, or a
        GPO conflict), not on the endpoint.

    So this script exists to find affected devices at fleet scale. You then fix the cause
    centrally. Leave the Remediation script field empty when you create the remediation.

    Exit 0  - healthy. WHfB policy delivered and UsePassportForWork is enabled.
    Exit 1  - issue found. Output names which check failed.

    The single line written to STDOUT is what appears in the Intune
    "Pre-remediation detection output" column, so it is kept short and parseable.

.EXAMPLE
    .\Detect-WHfBPolicyDelivery.ps1

    Run locally to see what Intune would record for this device.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks

    Run as   : System (64-bit PowerShell)
    Schedule : Daily
    Remediation script: leave empty. See the description above for why.
    Read-only. No changes are made to the device.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

try {
    $findings = [System.Collections.Generic.List[string]]::new()

    # -- 1. Is the tenant-scoped WHfB policy key present at all --------------
    $whfbBase = 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork'
    $usePfw   = $null
    $minPin   = $null
    $cloudTrust = $null
    $reqSecDev  = $null
    $tenantKeyFound = $false
    $mdmValues = @{}   # lowercase value name -> value, used for the GPO conflict check

    if (Test-Path $whfbBase) {
        foreach ($k in (Get-ChildItem $whfbBase -Recurse -ErrorAction SilentlyContinue)) {
            $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($n in $item.GetValueNames()) {
                $mdmValues[$n.ToLower()] = $item.GetValue($n)
                switch ($n) {
                    'UsePassportForWork'         { $usePfw     = $item.GetValue($n); $tenantKeyFound = $true }
                    'MinimumPINLength'           { $minPin     = $item.GetValue($n) }
                    'UseCloudTrustForOnPremAuth' { $cloudTrust = $item.GetValue($n) }
                    'RequireSecurityDevice'      { $reqSecDev  = $item.GetValue($n) }
                }
            }
        }
    }

    if (-not $tenantKeyFound) {
        $findings.Add('NoPolicyDelivered')
    }
    elseif ($usePfw -ne 1) {
        $findings.Add('WHfBDisabledByPolicy')
    }

    # -- 2. GPO conflict -----------------------------------------------------
    # GPO normally wins over MDM for the same setting. But merely HAVING a GPO copy is
    # extremely common on hybrid-joined fleets and is not itself a fault - if every device
    # flagged for that, the detection would be worthless. Only an actual DISAGREEMENT
    # between a GPO value and the matching MDM value is reported as an issue.
    $gpoBase     = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
    $gpoPresent  = $false
    $conflicts   = @()

    if (Test-Path $gpoBase) {
        foreach ($k in (@(Get-Item $gpoBase) + @(Get-ChildItem $gpoBase -Recurse -ErrorAction SilentlyContinue))) {
            $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($n in $item.GetValueNames()) {
                $gpoPresent = $true
                $leaf = $n.ToLower()
                if ($mdmValues.ContainsKey($leaf)) {
                    $gpoVal = [string]$item.GetValue($n)
                    $mdmVal = [string]$mdmValues[$leaf]
                    if ($gpoVal -ne $mdmVal) {
                        $conflicts += ('{0}(GPO={1},MDM={2})' -f $n, $gpoVal, $mdmVal)
                    }
                }
            }
        }
    }
    if ($conflicts.Count -gt 0) { $findings.Add('GPOConflict:' + ($conflicts -join '|')) }

    # -- 3. Is Hello actually provisioned for the signed-in user -------------
    $ngcSet = 'Unknown'
    try {
        $ds = dsregcmd /status
        $line = $ds | Where-Object { $_ -match '^\s*NgcSet\s*:' } | Select-Object -First 1
        if ($line) { $ngcSet = ($line -split ':')[1].Trim() }
    }
    catch { $ngcSet = 'Unknown' }

    if ($ngcSet -eq 'NO') { $findings.Add('HelloNotProvisioned') }

    # -- 4. Recent MDM sync failures ----------------------------------------
    # Only WHfB-relevant CSP failures count towards an ISSUE. A device can log dozens of
    # Event 404s for completely unrelated CSPs (broken ADMX ingestion, Display/ScaleFactor,
    # third-party ADMX) while Hello policy applies perfectly. Counting those would flag
    # healthy devices and train admins to ignore this detection.
    $mdmErrorsTotal = 0
    $mdmErrorsWHfB  = 0
    try {
        $ev = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
            Id        = 404
            StartTime = (Get-Date).AddDays(-3)
        } -ErrorAction SilentlyContinue

        $mdmErrorsTotal = @($ev).Count
        foreach ($e in $ev) {
            if ($e.Message -match 'PassportForWork|CredentialProviders') { $mdmErrorsWHfB++ }
        }
    }
    catch {
        $mdmErrorsTotal = 0
        $mdmErrorsWHfB  = 0
    }
    if ($mdmErrorsWHfB -gt 0) { $findings.Add(('WHfBCspErrors=' + $mdmErrorsWHfB)) }

    # -- Result --------------------------------------------------------------
    # WHfBCsp404 drives the ISSUE result. AllCsp404 is reported for context only, because a
    # high total with zero WHfB failures means the device has an unrelated CSP problem.
    $summary = 'Computer={0};PolicyDelivered={1};UsePassportForWork={2};MinimumPINLength={3};CloudTrust={4};RequireSecurityDevice={5};GPOPresent={6};NgcSet={7};WHfBCsp404Last3d={8};AllCsp404Last3d={9}' -f `
        $env:COMPUTERNAME,
        $(if ($tenantKeyFound) { 'Yes' } else { 'No' }),
        $(if ($null -ne $usePfw) { $usePfw } else { 'NotSet' }),
        $(if ($null -ne $minPin) { $minPin } else { 'NotSet' }),
        $(if ($null -ne $cloudTrust) { $cloudTrust } else { 'NotSet' }),
        $(if ($null -ne $reqSecDev) { $reqSecDev } else { 'NotSet' }),
        $(if ($gpoPresent) { 'Yes' } else { 'No' }),
        $ngcSet,
        $mdmErrorsWHfB,
        $mdmErrorsTotal

    if ($findings.Count -gt 0) {
        Write-Output ('ISSUE[{0}] {1}' -f ($findings -join ','), $summary)
        exit 1
    }

    Write-Output ('OK {0}' -f $summary)
    exit 0
}
catch {
    # Never exit 0 on an error. An unhandled failure must not look like a healthy device.
    Write-Output ('DETECTION_ERROR {0} {1}' -f $env:COMPUTERNAME, $_.Exception.Message)
    exit 1
}
