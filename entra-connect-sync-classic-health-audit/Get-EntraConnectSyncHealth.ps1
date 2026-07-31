<#
.SYNOPSIS
    Read-only health audit for classic Microsoft Entra Connect Sync (formerly Azure AD Connect).

.DESCRIPTION
    Runs LOCALLY on the Entra Connect Sync server using the ADSync PowerShell module. It reports
    on two things that make classic Connect Sync fail quietly:

      1. Scheduler drift - via Get-ADSyncScheduler. Flags a disabled sync cycle
         (SyncCycleEnabled = False), a suspended scheduler (SchedulerSuspended = True), a server
         left in staging mode (StagingModeEnabled = True, which imports and syncs but exports
         NOTHING to Entra ID), and an over-long effective sync interval.

      2. Persistent run errors - via Get-ADSyncConnector and Get-ADSyncRunProfileResult. Inspects
         the most recent run-profile results per connector and flags any run whose Result is not
         'success' (for example completed-export-errors).

    REPORT-ONLY. This script never enables, disables, starts, stops, resets, promotes, or modifies
    the scheduler, connectors, run profiles, or any synced object. It only reads. There are no
    Set-/Start-/Stop-/Invoke- calls anywhere in it.

    This is NOT a Microsoft Graph script. Classic Entra Connect Sync exposes no clean Graph
    job-status read surface, so its health has to be queried on the server itself. The script
    therefore requires the ADSync module to be present (it installs with Entra Connect Sync) and
    an elevated, local-administrator PowerShell session on the sync server.

    Exit codes:
        0 = healthy, no findings
        1 = script or query error (not elevated, ADSync module/cmdlets missing, or a query threw).
            Fail loud: the script never prints a clean "all healthy" result after a failed query.
        2 = findings detected (scheduler drift and/or persistent run errors)

.PARAMETER MaxSyncCycleIntervalHours
    The longest acceptable effective sync-cycle interval, in hours. If
    CurrentlyEffectiveSyncCycleInterval is longer than this, it is flagged. Default 24. The
    Microsoft default is 30 minutes and a delta sync must run at least once every 7 days.

.PARAMETER AllowStagingMode
    Treat StagingModeEnabled = True as expected (for a deliberate, documented standby/passive
    server) instead of flagging it. The default is to flag staging mode, because a forgotten
    staging server that exports nothing is the single most common silent failure.

.PARAMETER LookbackRuns
    Number of most-recent run-profile results to inspect per connector. Default 5.

.PARAMETER ExportCsv
    When set, writes all findings to a CSV file.

.PARAMETER CsvPath
    Path for the CSV file when -ExportCsv is used. Defaults to a timestamped file in the temp folder.

.EXAMPLE
    .\Get-EntraConnectSyncHealth.ps1
    Runs the audit on the local Entra Connect Sync server and prints the result.

.EXAMPLE
    .\Get-EntraConnectSyncHealth.ps1 -AllowStagingMode -ExportCsv
    Runs the audit on a known, deliberate standby server (does not flag staging mode) and exports
    findings to CSV.

.NOTES
    Author : Imran Awan / EndpointWeekly
    Run on the Entra Connect Sync server itself, in an elevated Windows PowerShell session.
    Verified cmdlets: Get-ADSyncScheduler, Get-ADSyncConnector, Get-ADSyncRunProfileResult
    (ADSync PowerShell reference on Microsoft Learn).
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$MaxSyncCycleIntervalHours = 24,

    [switch]$AllowStagingMode,

    [ValidateRange(1, 50)]
    [int]$LookbackRuns = 5,

    [switch]$ExportCsv,

    [string]$CsvPath = "$env:TEMP\EntraConnectSyncHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false
$findings = New-Object System.Collections.Generic.List[object]

function Write-Log {
    param(
        [ValidateSet('INFO', 'WARN', 'FAIL', 'PASS', 'ERROR')]
        [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host ("[{0}] [{1,-5}] {2}" -f $ts, $Level, $Message)
}

function Add-Finding {
    param(
        [string]$Area,
        [string]$Check,
        [string]$Severity,
        [string]$Detail
    )
    $findings.Add([pscustomobject]@{
            Time     = (Get-Date).ToString('s')
            Server   = $env:COMPUTERNAME
            Area     = $Area
            Check    = $Check
            Severity = $Severity
            Detail   = $Detail
        })
    $level = if ($Severity -eq 'High') { 'FAIL' } else { 'WARN' }
    Write-Log $level ("{0}: {1}" -f $Check, $Detail)
}

Write-Log 'INFO' ("Entra Connect Sync health audit starting on {0}" -f $env:COMPUTERNAME)

# --- Preconditions: elevation, module, cmdlets. Any failure here is a fail-loud exit 1. ---

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log 'ERROR' 'This script must run in an elevated (local administrator) session on the Connect Sync server.'
        exit 1
    }
}
catch {
    Write-Log 'ERROR' ("Could not determine elevation state: {0}" -f $_.Exception.Message)
    exit 1
}

try {
    Import-Module ADSync -ErrorAction Stop
    Write-Log 'INFO' 'ADSync module loaded (querying the local sync engine, not Microsoft Graph).'
}
catch {
    Write-Log 'ERROR' ("The ADSync PowerShell module could not be loaded: {0}" -f $_.Exception.Message)
    Write-Log 'ERROR' 'Run this on the Entra Connect Sync server, where the ADSync module is installed.'
    exit 1
}

$requiredCmdlets = @('Get-ADSyncScheduler', 'Get-ADSyncConnector', 'Get-ADSyncRunProfileResult')
foreach ($cmd in $requiredCmdlets) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Log 'ERROR' ("Required cmdlet '{0}' is not available. This build of Entra Connect Sync may be too old, or the module did not load fully." -f $cmd)
        exit 1
    }
}

# --- Check 1: scheduler configuration ---

Write-Log 'INFO' '--- Scheduler configuration (Get-ADSyncScheduler) ---'
try {
    $sched = Get-ADSyncScheduler -ErrorAction Stop
}
catch {
    Write-Log 'ERROR' ("Get-ADSyncScheduler failed: {0}" -f $_.Exception.Message)
    exit 1
}

Write-Log 'INFO' ("  SyncCycleEnabled                    : {0}" -f $sched.SyncCycleEnabled)
Write-Log 'INFO' ("  StagingModeEnabled                  : {0}" -f $sched.StagingModeEnabled)
Write-Log 'INFO' ("  SchedulerSuspended                  : {0}" -f $sched.SchedulerSuspended)
Write-Log 'INFO' ("  MaintenanceEnabled                  : {0}" -f $sched.MaintenanceEnabled)
Write-Log 'INFO' ("  CurrentlyEffectiveSyncCycleInterval : {0}" -f $sched.CurrentlyEffectiveSyncCycleInterval)
Write-Log 'INFO' ("  NextSyncCyclePolicyType             : {0}" -f $sched.NextSyncCyclePolicyType)
Write-Log 'INFO' ("  NextSyncCycleStartTimeInUTC         : {0}" -f $sched.NextSyncCycleStartTimeInUTC)

if ($sched.SyncCycleEnabled -eq $false) {
    Add-Finding -Area 'Scheduler' -Check 'SyncCycleEnabled' -Severity 'High' -Detail 'Sync cycle is DISABLED (SyncCycleEnabled=False). Import, sync and export are not running. Often left disabled after a config change.'
}
else {
    Write-Log 'PASS' '  SyncCycleEnabled is True'
}

if ($sched.SchedulerSuspended -eq $true) {
    Add-Finding -Area 'Scheduler' -Check 'SchedulerSuspended' -Severity 'High' -Detail 'Scheduler is SUSPENDED (SchedulerSuspended=True). Connect sets this during an upgrade; a half-finished upgrade can leave it suspended so nothing runs.'
}
else {
    Write-Log 'PASS' '  SchedulerSuspended is False'
}

if ($sched.StagingModeEnabled -eq $true) {
    if ($AllowStagingMode) {
        Write-Log 'INFO' '  StagingModeEnabled is True and -AllowStagingMode was set: treated as an expected standby server.'
    }
    else {
        Add-Finding -Area 'Scheduler' -Check 'StagingModeEnabled' -Severity 'High' -Detail 'Server is in STAGING MODE (StagingModeEnabled=True). Import and sync run but NOTHING is exported to Entra ID. If this is not a deliberate standby server, objects are silently going stale.'
    }
}
else {
    Write-Log 'PASS' '  StagingModeEnabled is False'
}

# Effective interval is a TimeSpan. Guard the type before comparing.
$interval = $sched.CurrentlyEffectiveSyncCycleInterval
if ($interval -is [System.TimeSpan]) {
    if ($interval.TotalHours -gt $MaxSyncCycleIntervalHours) {
        Add-Finding -Area 'Scheduler' -Check 'SyncCycleInterval' -Severity 'Medium' -Detail ("Effective sync interval is {0} (over the {1}h threshold). A delta sync must run at least once every 7 days or a full sync becomes necessary." -f $interval, $MaxSyncCycleIntervalHours)
    }
    else {
        Write-Log 'PASS' ("  Effective sync interval {0} is within the {1}h threshold" -f $interval, $MaxSyncCycleIntervalHours)
    }
}
else {
    Write-Log 'WARN' '  CurrentlyEffectiveSyncCycleInterval was not a TimeSpan - skipping interval check.'
}

# --- Check 2: connector run-profile results ---

Write-Log 'INFO' ("--- Connector run-profile results (last {0} runs per connector) ---" -f $LookbackRuns)
try {
    $connectors = @(Get-ADSyncConnector -ErrorAction Stop)
}
catch {
    Write-Log 'ERROR' ("Get-ADSyncConnector failed: {0}" -f $_.Exception.Message)
    exit 1
}

if ($connectors.Count -eq 0) {
    Write-Log 'ERROR' 'Get-ADSyncConnector returned no connectors. A configured sync server always has connectors; treating this as a query problem.'
    exit 1
}

foreach ($conn in $connectors) {
    $connName = $conn.Name
    try {
        $runs = @(Get-ADSyncRunProfileResult -ConnectorId $conn.Identifier -NumberRequested $LookbackRuns -ErrorAction Stop)
    }
    catch {
        Write-Log 'ERROR' ("Get-ADSyncRunProfileResult failed for connector '{0}': {1}" -f $connName, $_.Exception.Message)
        $script:hadError = $true
        continue
    }

    if ($runs.Count -eq 0) {
        Write-Log 'WARN' ("  {0}: no run history returned in the lookback window." -f $connName)
        continue
    }

    foreach ($run in $runs) {
        # The status string lives on the Result property. If the object shape is not what we
        # expect, fail loud rather than silently reporting "no errors".
        $resultProp = $run.PSObject.Properties['Result']
        if (-not $resultProp) {
            Write-Log 'ERROR' ("Run result object for connector '{0}' has no 'Result' property. Cannot evaluate run status; failing loud." -f $connName)
            $script:hadError = $true
            continue
        }

        $resultText = [string]$run.Result
        $profileName = if ($run.PSObject.Properties['RunProfileName']) { [string]$run.RunProfileName } else { 'run-profile' }

        if ($resultText -eq 'success') {
            Write-Log 'PASS' ("  {0} / {1}: success" -f $connName, $profileName)
        }
        elseif ($resultText -match 'error') {
            Add-Finding -Area 'RunProfile' -Check 'ConnectorRunResult' -Severity 'High' -Detail ("{0} / {1} last result '{2}'. Persistent export/sync errors accumulate in the Operations tab that nobody opens." -f $connName, $profileName, $resultText)
        }
        elseif ([string]::IsNullOrWhiteSpace($resultText)) {
            Write-Log 'WARN' ("  {0} / {1}: empty run result - skipping." -f $connName, $profileName)
        }
        else {
            Add-Finding -Area 'RunProfile' -Check 'ConnectorRunResult' -Severity 'Medium' -Detail ("{0} / {1} last result '{2}' (not 'success'). Review this run in the Synchronization Service Manager Operations tab." -f $connName, $profileName, $resultText)
        }
    }
}

# --- Result ---

Write-Log 'INFO' '--- RESULT ---'

if ($ExportCsv) {
    try {
        $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log 'INFO' ("Findings written to {0}" -f $CsvPath)
    }
    catch {
        Write-Log 'ERROR' ("Failed to write CSV to '{0}': {1}" -f $CsvPath, $_.Exception.Message)
        $script:hadError = $true
    }
}

if ($script:hadError) {
    Write-Log 'ERROR' 'One or more queries failed. Results are incomplete - NOT reporting a clean bill of health. Fix the errors above and re-run.'
    exit 1
}

if ($findings.Count -gt 0) {
    Write-Log 'FAIL' ("UNHEALTHY - {0} finding(s). Classic Connect Sync may be importing and syncing while exporting nothing, or accumulating run errors." -f $findings.Count)
    exit 2
}

Write-Log 'PASS' 'HEALTHY - scheduler is enabled, not suspended, not stuck in staging mode, interval is sane, and recent connector runs succeeded.'
exit 0
