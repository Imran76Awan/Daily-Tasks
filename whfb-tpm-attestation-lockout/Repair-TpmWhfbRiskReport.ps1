<#
.SYNOPSIS
    Intune Proactive Remediation - REMEDIATION script for TPM/WHfB hardware-backing risk.

.DESCRIPTION
    This is deliberately REPORT-ONLY. It does not, and should not, "fix" either
    condition the detection script finds, because there is no safe automatic fix:

      - TPM lockout usually self-heals on a cooldown; clearing the TPM to force a
        reset would DESTROY every sealed Hello key on the device and force every
        user to re-provision. That is worse than the lockout.
      - RequireSecurityDevice is a WHfB policy setting delivered via Intune/GPO.
        Writing that registry value directly from a remediation script can race
        or conflict with the real MDM policy channel. The correct fix is to
        assign the "Require Security Device" setting through a Settings Catalog
        (or GPO) policy - not to patch the registry from here.

    What this script actually does: re-collects the same signals the detection
    script found, writes them to a local log file and to the Application event
    log (source 'WHfB-TPM-Remediation') so they surface in Intune's remediation
    output and can be alerted on via Log Analytics / Sentinel. It always exits 0
    (Intune will show "remediated" for this cycle) - that reflects "detected and
    logged for admin follow-up", NOT "problem solved". If nothing changes on the
    device, the next detection cycle will flag it again and this script will log
    it again - that repetition is intentional; it is your audit trail, not noise
    to suppress.

.NOTES
    Author      : Imran Awan (EndpointWeekly)
    Blog        : https://endpointweekly.com/blog/whfb-tpm-attestation-lockout.html
    Deploy as   : Intune Proactive Remediation - Remediation script (paired with
                  Detect-TpmWhfbRisk.ps1)
    Run context : Logged-on user (must match the detection script's context)
    Action taken: NONE that changes TPM, WHfB, or policy state. Logging only.
#>

$logDir = Join-Path $env:ProgramData 'EndpointWeekly\WHfBTpmRisk'
New-Item -Path $logDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
$logFile = Join-Path $logDir 'tpm-whfb-risk-log.csv'

$tpm = $null
try { $tpm = Get-Tpm -ErrorAction Stop } catch { }

$requireSecDevice = $null
foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
                    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork')) {
    if (Test-Path $root) {
        Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $v.RequireSecurityDevice) { $requireSecDevice = $v.RequireSecurityDevice }
        }
    }
}

$record = [PSCustomObject]@{
    TimeUtc               = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ComputerName          = $env:COMPUTERNAME
    User                  = $env:USERNAME
    TpmPresent            = if ($tpm) { $tpm.TpmPresent } else { 'Unknown' }
    TpmReady              = if ($tpm) { $tpm.TpmReady } else { 'Unknown' }
    LockedOut             = if ($tpm) { $tpm.LockedOut } else { 'Unknown' }
    LockoutCount          = if ($tpm) { $tpm.LockoutCount } else { 'Unknown' }
    RequireSecurityDevice = if ($null -ne $requireSecDevice) { $requireSecDevice } else { 'not set' }
}

# Local CSV audit trail (append)
$record | Export-Csv -Path $logFile -Append -NoTypeInformation -Encoding UTF8

# Application event log (best-effort; needs the source registered once, which
# requires local admin rights - Intune remediation scripts run as SYSTEM by default)
$src = 'WHfB-TPM-Remediation'
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
        New-EventLog -LogName Application -Source $src -ErrorAction Stop
    }
    $msg = "TPM/WHfB risk detected (report only, no action taken).`n" + ($record | Format-List | Out-String)
    Write-EventLog -LogName Application -Source $src -EventId 7700 -EntryType Warning -Message $msg
} catch {
    Write-Output "Could not write to the Application event log: $($_.Exception.Message)"
}

Write-Output "Logged TPM/WHfB risk finding to $logFile and the Application event log (source: $src). No device, WHfB, or policy state was changed - see script header for why."
exit 0
