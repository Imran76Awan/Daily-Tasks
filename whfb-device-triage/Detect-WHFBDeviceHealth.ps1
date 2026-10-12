<#
.SYNOPSIS
    Intune Proactive Remediation DETECTION: is Windows Hello for Business broken on this device?

.DESCRIPTION
    Read-only. Runs the same blocking checks as Get-WHFBDeviceReport.ps1, in the same order, so a
    device flagged here shows the identical reason in the full report.

    Exit 1 (issue found, remediation runs) when ANY of these is true:
      * AzureAdJoined is not YES
      * the device registration certificate has expired
      * the TPM is present but not ready
      * NgcSet is NO
      * NgcSet is YES but no NGC container exists on disk
      * AzureAdPrt is not YES
      * NgcSvc or KeyIso is stopped
      * PassportForWork policy explicitly sets Enabled = 0

    Exit 0 (healthy) otherwise.

    Deliberately NOT treated as a failure:
      * WbioSrvc and NgcCtnrSvc stopped - both are trigger-started by design, so "Stopped" is the
        normal resting state and flagging it reports healthy devices as broken.
      * a password-heavy sign-in history - that is an adoption question, not a device fault, and
        remediation cannot fix a human habit.
      * audit policy gaps - they affect reporting accuracy, not the user.

.PARAMETER None
    Proactive Remediations call detection scripts with no parameters.

.EXAMPLE
    .\Detect-WHFBDeviceHealth.ps1
    Prints one summary line and sets the exit code. This is how Intune runs it.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/whfb-device-triage-report-offline-viewer.html
    Repo    : https://github.com/Imran76Awan/Daily-Tasks
    Context : Run as SYSTEM, 64-bit. Leave "Run this script using the logged-on credentials" OFF.
              NgcSet and AzureAdPrt are per-user values, so this reports the state SYSTEM can see;
              pair it with the full report when you need the signed-in user's own view.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$issues = New-Object System.Collections.Generic.List[string]

try {
    $dsreg = (dsregcmd /status) -join "`n"
    function Get-DsregField([string]$Name) {
        if ($dsreg -match "(?m)^[ \t]*$Name[ \t]*:[ \t]*(.*)$") { return $Matches[1].TrimEnd() }
        return ''
    }

    $aadJoined = Get-DsregField 'AzureAdJoined'
    $ngcSet    = Get-DsregField 'NgcSet'
    $prt       = Get-DsregField 'AzureAdPrt'

    if ($aadJoined -ne 'YES') { $issues.Add('NotJoined') }

    # Device registration certificate
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
            Where-Object { $_.Issuer -match 'MS-Organization-Access' } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
        if ($cert -and $cert.NotAfter -lt (Get-Date)) { $issues.Add('DeviceCertExpired') }
    } catch { }

    # TPM. Only a failure when the chip is present but not ready - a device with no TPM at all is
    # a different conversation (hardware), not something remediation can act on.
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and -not $tpm.TpmReady) { $issues.Add('TpmNotReady') }
    } catch { }

    if ($ngcSet -eq 'NO') { $issues.Add('NgcNotSet') }

    if ($ngcSet -eq 'YES') {
        $ngcPath = Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
        try {
            $count = @(Get-ChildItem -LiteralPath $ngcPath -ErrorAction Stop).Count
            if ($count -eq 0) { $issues.Add('NgcContainerMissing') }
        } catch { }
    }

    if ($prt -ne 'YES') { $issues.Add('NoPrt') }

    foreach ($name in 'NgcSvc', 'KeyIso') {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { $issues.Add('ServiceStopped:' + $name) }
    }

    try {
        $enabled = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'Enabled' -ErrorAction Stop).Enabled
        if ("$enabled" -eq '0') { $issues.Add('PolicyDisabled') }
    } catch { }

    if ($issues.Count -gt 0) {
        Write-Output ("WHfB issues: " + ($issues -join ', '))
        exit 1
    }

    Write-Output 'WHfB healthy'
    exit 0
}
catch {
    # Fail loud. A detection script that swallows its own error and exits 0 reports a broken
    # device as healthy, which is worse than reporting nothing.
    Write-Output ("WHfB detection failed: " + $_.Exception.Message)
    exit 1
}
