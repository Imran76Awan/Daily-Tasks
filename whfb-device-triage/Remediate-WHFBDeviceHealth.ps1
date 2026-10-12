<#
.SYNOPSIS
    Intune Proactive Remediation: fixes only the Windows Hello for Business faults that are safe
    to fix without a human, and refuses the rest on purpose.

.DESCRIPTION
    Read the refusal list before you deploy this. It is the important half.

    WILL fix, because these are safe, reversible and need no user interaction:
      * NgcSvc or KeyIso stopped          -> starts the service
      * PassportForWork Enabled = 0        -> reports it, does NOT edit the key (see below)
      * no single sign-on token            -> triggers the device registration task and an MDM sync
      * device registration certificate expired -> triggers the registration task to renew it

    WILL NOT fix, by design:
      * NgcSet = NO, or a missing NGC container. The repair is to delete the user's Hello container
        and have them enrol again. That is destructive: it wipes their PIN and biometrics, it needs
        the user present, and done at fleet scale by a scheduled task it is indistinguishable from
        an attack. This script reports it and exits non-zero so the device stays visible.
      * TPM not ready. Clearing a TPM destroys every key on the device, including BitLocker
        protectors. Never automate it.
      * Device not joined. Re-joining is an enrolment decision, not a repair.
      * PassportForWork Enabled = 0. The registry key is the result of a policy, so writing to it
        is undone at the next sync and hides a real policy problem. Fix the policy instead.

    Every action is logged to the console (captured in the Intune output) and to a local log file.

.PARAMETER LogPath
    Where to append the log. Defaults to ProgramData\EndpointWeekly\whfb-remediation.log.

.EXAMPLE
    .\Remediate-WHFBDeviceHealth.ps1
    Performs the safe repairs and exits 0 only if nothing is left outstanding.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/whfb-device-triage-report-offline-viewer.html
    Repo    : https://github.com/Imran76Awan/Daily-Tasks
    Context : Run as SYSTEM, 64-bit. Pairs with Detect-WHFBDeviceHealth.ps1.
#>
[CmdletBinding()]
param(
    [string]$LogPath = (Join-Path $env:ProgramData 'EndpointWeekly\whfb-remediation.log')
)

$ErrorActionPreference = 'Continue'
$actions   = New-Object System.Collections.Generic.List[string]
$refused   = New-Object System.Collections.Generic.List[string]
$failures  = New-Object System.Collections.Generic.List[string]

function Write-Log([string]$Message) {
    $line = ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
    Write-Output $line
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $LogPath -Value $line -ErrorAction Stop
    } catch { }
}

Write-Log 'Remediation started'

# ---------------------------------------------------------------- 1. stopped services
foreach ($name in 'NgcSvc', 'KeyIso') {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        try {
            Start-Service -Name $name -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc.Refresh()
            if ($svc.Status -eq 'Running') {
                $actions.Add("started $name")
                Write-Log "FIXED  started $name"
            } else {
                $failures.Add("$name did not reach Running")
                Write-Log "FAILED $name did not reach Running"
            }
        } catch {
            $failures.Add("could not start ${name}: $($_.Exception.Message)")
            Write-Log "FAILED could not start ${name}: $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------- 2. read current state
$dsreg = ''
try { $dsreg = (dsregcmd /status) -join "`n" } catch { }
function Get-DsregField([string]$Name) {
    if ($dsreg -match "(?m)^[ \t]*$Name[ \t]*:[ \t]*(.*)$") { return $Matches[1].TrimEnd() }
    return ''
}
$aadJoined = Get-DsregField 'AzureAdJoined'
$ngcSet    = Get-DsregField 'NgcSet'
$prt       = Get-DsregField 'AzureAdPrt'

$certExpired = $false
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
        Where-Object { $_.Issuer -match 'MS-Organization-Access' } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($cert -and $cert.NotAfter -lt (Get-Date)) { $certExpired = $true }
} catch { }

# ---------------------------------------------------------------- 3. safe nudges
# Both of these only ask Windows to retry work it already schedules itself. Neither deletes
# anything, and both are no-ops on a healthy device.
if ($prt -ne 'YES' -or $certExpired) {
    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Workplace Join\' -TaskName 'Automatic-Device-Join' -ErrorAction Stop
        Start-ScheduledTask -InputObject $task -ErrorAction Stop
        $actions.Add('triggered Automatic-Device-Join')
        Write-Log 'FIXED  triggered the Automatic-Device-Join task'
    } catch {
        $failures.Add("could not trigger Automatic-Device-Join: $($_.Exception.Message)")
        Write-Log "FAILED could not trigger Automatic-Device-Join: $($_.Exception.Message)"
    }

    try {
        $push = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'PushLaunch' } | Select-Object -First 1
        if ($push) {
            Start-ScheduledTask -InputObject $push -ErrorAction Stop
            $actions.Add('triggered an MDM sync')
            Write-Log 'FIXED  triggered an MDM sync (PushLaunch)'
        }
    } catch {
        Write-Log "NOTE   could not trigger the MDM sync: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- 4. the refusals
if ($ngcSet -eq 'NO') {
    $refused.Add('NgcSet is NO - the user must set Windows Hello up again. Not automated: the repair deletes their PIN and biometrics and needs them present.')
}
if ($ngcSet -eq 'YES') {
    $ngcPath = Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
    try {
        if (@(Get-ChildItem -LiteralPath $ngcPath -ErrorAction Stop).Count -eq 0) {
            $refused.Add('NGC container is missing while NgcSet is YES - needs a supervised re-enrolment, not a scheduled task.')
        }
    } catch { }
}
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm.TpmPresent -and -not $tpm.TpmReady) {
        $refused.Add('TPM is not ready - clearing a TPM destroys BitLocker protectors and every device key. Handle it in a planned change.')
    }
} catch { }
if ($aadJoined -ne 'YES') {
    $refused.Add('Device is not joined to the cloud directory - re-joining is an enrolment decision, not a repair.')
}
try {
    $enabled = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'Enabled' -ErrorAction Stop).Enabled
    if ("$enabled" -eq '0') {
        $refused.Add('Policy sets PassportForWork Enabled = 0 - fix the Intune profile or GPO. Writing the key here is reverted at the next sync.')
    }
} catch { }

# ---------------------------------------------------------------- 5. result
foreach ($r in $refused) { Write-Log ('REFUSED ' + $r) }

$summary = ('Actions: {0}. Refused: {1}. Failures: {2}.' -f
    $(if ($actions.Count) { $actions -join '; ' } else { 'none needed' }),
    $refused.Count,
    $failures.Count)
Write-Log $summary

if ($failures.Count -gt 0 -or $refused.Count -gt 0) {
    Write-Output $summary
    exit 1
}

Write-Output $summary
exit 0
