<#
.SYNOPSIS
    Read-only diagnostic snapshot of the Intune Management Extension (IME) on the local Windows device.

.DESCRIPTION
    Checks three things that between them explain almost every "stuck processing" Win32 app,
    PowerShell script, or Proactive Remediation ticket on a device managed by Microsoft Intune:

      1. The state of the "IntuneManagementExtension" Windows service (running / stopped / missing).
      2. Whether the IME log folder exists under C:\ProgramData\Microsoft\IntuneManagementExtension\Logs,
         and how recently each log file was last written to (a healthy agent writes to
         IntuneManagementExtension.log roughly every 8 hours at minimum, per Microsoft's documented
         IME check-in cadence).
      3. A read-only scan of AppWorkload.log (Win32 app activity) and AgentExecutor.log (PowerShell
         script execution) for lines that reference pending, failed, or error states, so you get a
         count of "things the agent is currently unhappy about" without opening the raw logs by hand.

    This script makes NO changes anywhere. It does not restart the service, does not touch the
    registry, does not delete or rotate any log file, and does not call any Intune or Graph API.
    It only reads local service state and local log files.

    Log file names and the log folder path are documented by Microsoft at:
    https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension

.NOTES
    Author        : EndpointWeekly (Imran Awan)
    Blog post     : https://endpointweekly.com/blog/intune-management-extension-overview-win32-apps.html
    Read-only     : Yes  -  no writes, no service actions, no remote calls.
    Requirements  : Run in an elevated PowerShell session. The IME log folder under ProgramData
                    is ACL-restricted; a non-elevated session will typically fail to read it and
                    this script will report that plainly rather than silently returning empty results.

    Service name and log file names below (IntuneManagementExtension, IntuneManagementExtension.log,
    AppWorkload.log, AgentExecutor.log, AppActionProcessor.log, ClientHealth.log, HealthScripts.log)
    are documented directly by Microsoft. If Microsoft changes these in a future IME release and this
    script reports "not found" for a log that should exist, verify against the current Microsoft Learn
    article above before assuming the device itself is broken.

.EXAMPLE
    .\Get-IMEHealthCheck.ps1

    Runs a full health check against the default log path and prints a summary to the console.

.EXAMPLE
    .\Get-IMEHealthCheck.ps1 -StaleAfterHours 12 -TailLines 300

    Flags log files as stale if untouched for more than 12 hours (default is 24), and scans the
    last 300 lines of each parsed log instead of the default 200.
#>

[CmdletBinding()]
param(
    # Path to the IME log folder. Override only for testing against a copied/offline log set  - 
    # on a live device this must be the real path documented by Microsoft.
    [string]$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs",

    # Windows service name for the Intune Management Extension, as documented by Microsoft.
    [string]$ServiceName = "IntuneManagementExtension",

    # How many hours since last write before a log file is flagged as stale.
    # The IME checks in with Intune roughly every 8 hours independent of MDM sync, so 24 hours
    # gives headroom for a device that has been asleep or offline for part of a day.
    [int]$StaleAfterHours = 24,

    # How many of the most recent lines to scan per log file for pending/failed/error markers.
    [int]$TailLines = 200
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

$result = [ordered]@{
    CollectedAtUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ComputerName     = $env:COMPUTERNAME
    IsElevated       = $false
    ServiceName      = $ServiceName
    ServiceFound     = $false
    ServiceStatus    = $null
    ServiceStartType = $null
    LogPath          = $LogPath
    LogPathExists    = $false
    LogFiles         = @()
    StaleLogFiles    = @()
    ActivityFindings = @()
    OverallHealth    = 'Unknown'
    Warnings         = @()
}

# --- Elevation check (read-only check, no self-elevation attempted) ---
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $result.IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    $result.Warnings += "Could not determine elevation state: $($_.Exception.Message)"
}

if (-not $result.IsElevated) {
    $result.Warnings += "Not running elevated. The IME log folder is ACL-restricted to Administrators/SYSTEM  -  log reads below may fail or return partial results. Re-run this script from an elevated PowerShell session for a reliable result."
}

Write-Section "Intune Management Extension service"

try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    $result.ServiceFound     = $true
    $result.ServiceStatus    = $svc.Status.ToString()
    $result.ServiceStartType = $svc.StartType.ToString()
    Write-Host ("Service '{0}' found  -  Status: {1}, StartType: {2}" -f $ServiceName, $svc.Status, $svc.StartType)

    if ($svc.Status -ne 'Running') {
        $result.Warnings += "Service '$ServiceName' is not running (Status: $($svc.Status)). This alone will cause every Win32 app, script, and remediation assigned to this device to stall  -  the agent cannot process anything while stopped."
    }
}
catch {
    $result.ServiceFound = $false
    $result.Warnings += "Service '$ServiceName' was not found on this device. Either the IME has never installed (no Win32 app, PowerShell script, remediation, or custom compliance policy has ever been assigned to this device/user), or it was removed per Microsoft's documented removal conditions (no scripts assigned, device unmanaged, or 24h+ irrecoverable state)."
    Write-Warning "Service '$ServiceName' not found. See warnings in the summary below."
}

Write-Section "IME log folder"

if (Test-Path -LiteralPath $LogPath) {
    $result.LogPathExists = $true
    Write-Host "Log folder exists: $LogPath"

    try {
        $logFiles = Get-ChildItem -LiteralPath $LogPath -Filter '*.log' -File -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending
    }
    catch {
        $result.Warnings += "Found the log folder but could not enumerate its contents: $($_.Exception.Message). This is almost always a permissions issue  -  re-run elevated."
        $logFiles = @()
    }

    if (-not $logFiles -or $logFiles.Count -eq 0) {
        $result.Warnings += "Log folder exists but no .log files were readable inside it. If you are not running elevated, this is expected  -  re-run as Administrator."
    }

    # The IME rotates its logs and keeps timestamped copies (e.g. AppWorkload-20260722-113547.log).
    # Those rotated copies will legitimately never be "fresh" again, so they're excluded from the
    # staleness check entirely. Staleness is only assessed against the small set of core, always-on
    # log files Microsoft documents by name -- the files the running agent should be actively writing
    # to on a regular cadence. Feature-specific logs (e.g. remediation-script logs that only get
    # written when that specific remediation runs) are listed but never flagged as stale.
    $rotatedNamePattern = '-\d{8}-\d{6}\.log$'
    $coreLogNames = @(
        'IntuneManagementExtension.log', 'AppWorkload.log', 'AgentExecutor.log',
        'AppActionProcessor.log', 'ClientHealth.log', 'HealthScripts.log',
        'Win32AppInventory.log', 'ClientCertCheck.log', 'DeviceHealthMonitoring.log',
        'NotificationInfraLogs.log', 'Sensor.log'
    )

    foreach ($f in $logFiles) {
        $ageHours = [Math]::Round(((Get-Date) - $f.LastWriteTime).TotalHours, 1)
        $isRotated = $f.Name -match $rotatedNamePattern
        $isCoreLog = $coreLogNames -contains $f.Name
        $entry = [ordered]@{
            Name          = $f.Name
            LastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            AgeHours      = $ageHours
            SizeKB        = [Math]::Round($f.Length / 1KB, 1)
            IsRotatedCopy = $isRotated
        }
        $result.LogFiles += $entry

        if ($isCoreLog -and -not $isRotated -and $ageHours -gt $StaleAfterHours) {
            $result.StaleLogFiles += $f.Name
        }

        Write-Host ("  {0,-42} last written {1,6} hours ago  ({2} KB){3}" -f $f.Name, $ageHours, $entry.SizeKB, $(if ($isRotated) { '  [rotated copy]' } else { '' }))
    }

    if ($result.StaleLogFiles.Count -gt 0) {
        $svcNote = if ($result.ServiceFound -and $result.ServiceStatus -eq 'Running') {
            'The service is reported as Running, so this points to a check-in timing issue (or a stalled job) rather than the service being down.'
        } else {
            'Combined with a service that is not reported as Running, this points to the agent not having checked in recently rather than a single failed job.'
        }
        $result.Warnings += "The following core IME log(s) have not been written to in over $StaleAfterHours hours: $($result.StaleLogFiles -join ', '). $svcNote"
    }
}
else {
    $result.LogPathExists = $false
    $result.Warnings += "Log folder '$LogPath' does not exist. This is expected if the IME has never installed on this device. If a Win32 app or script HAS been assigned here, this is itself the problem  -  the agent never downloaded in the first place. See 'Intune management extension doesn't download' in Microsoft's troubleshooting guidance."
    Write-Warning "Log folder not found: $LogPath"
}

Write-Section "Scanning AppWorkload.log and AgentExecutor.log for pending / failed / error markers"

$logsToScan = @(
    @{ Name = 'AppWorkload.log';   Purpose = 'Win32 app deployment activity' }
    @{ Name = 'AgentExecutor.log'; Purpose = 'PowerShell script execution' }
)

# Patterns are deliberately broad and case-insensitive  -  this is a triage aid to point you at the
# right lines to read yourself, not an authoritative pass/fail parser of Microsoft's log format.
$pattern = '(?i)\b(fail(ed|ure)?|error|pending|timeout|timed out|denied|exception)\b'

foreach ($target in $logsToScan) {
    $fullPath = Join-Path -Path $LogPath -ChildPath $target.Name

    if (-not (Test-Path -LiteralPath $fullPath)) {
        $result.ActivityFindings += [ordered]@{
            LogFile = $target.Name
            Purpose = $target.Purpose
            Status  = 'Not found'
            Matches = 0
        }
        Write-Host "$($target.Name)  -  not found (skipped)"
        continue
    }

    try {
        $lines = Get-Content -LiteralPath $fullPath -Tail $TailLines -ErrorAction Stop
        $matchLines = $lines | Select-String -Pattern $pattern
        $matchCount = @($matchLines).Count

        $result.ActivityFindings += [ordered]@{
            LogFile = $target.Name
            Purpose = $target.Purpose
            Status  = 'Scanned'
            Matches = $matchCount
        }

        Write-Host ("{0,-20} ({1})  -  {2} of last {3} lines matched pending/fail/error markers" -f `
            $target.Name, $target.Purpose, $matchCount, [Math]::Min($TailLines, $lines.Count))

        if ($matchCount -gt 0) {
            Write-Host "  Sample (most recent match):" -ForegroundColor Yellow
            $sample = $matchLines | Select-Object -Last 1
            Write-Host "  $($sample.Line.Trim())" -ForegroundColor DarkYellow
        }
    }
    catch {
        $result.ActivityFindings += [ordered]@{
            LogFile = $target.Name
            Purpose = $target.Purpose
            Status  = "Read error: $($_.Exception.Message)"
            Matches = $null
        }
        $result.Warnings += "Could not read $($target.Name): $($_.Exception.Message)"
        Write-Warning "Could not read $($target.Name): $($_.Exception.Message)"
    }
}

# --- Overall health verdict (best-effort  -  a triage signal, not a guarantee) ---
if (-not $result.ServiceFound) {
    $result.OverallHealth = 'IME not installed on this device'
}
elseif ($result.ServiceStatus -ne 'Running') {
    $result.OverallHealth = 'Unhealthy  -  service not running'
}
elseif ($result.StaleLogFiles.Count -gt 0) {
    $result.OverallHealth = 'Warning  -  logs stale, agent may not be checking in'
}
elseif (($result.ActivityFindings | Where-Object { $_.Matches -gt 0 }).Count -gt 0) {
    $result.OverallHealth = 'Warning  -  recent pending/fail/error entries found in logs'
}
else {
    $result.OverallHealth = 'Healthy  -  service running, logs current, no recent error markers found'
}

Write-Section "Summary"

Write-Host "Overall health : $($result.OverallHealth)" -ForegroundColor $(
    switch -Wildcard ($result.OverallHealth) {
        'Healthy*' { 'Green' }
        'Warning*' { 'Yellow' }
        default    { 'Red' }
    }
)

if ($result.Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($w in $result.Warnings) {
        Write-Host "  - $w" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Full structured result object returned to the pipeline (pipe to Format-List / ConvertTo-Json for detail)." -ForegroundColor DarkGray

[PSCustomObject]$result
