#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit that detects drift between modern Windows LAPS and legacy
    Microsoft LAPS (AdmPwd) on the local device after a migration.

.DESCRIPTION
    Get-LapsMigrationDrift.ps1 is a DEVICE-SIDE, REPORT-ONLY script. It never
    creates, modifies, enables, disables, resets, rotates, or removes anything.
    It only reads local configuration and state.

    What it reads:
      1. The Windows LAPS policy roots in the registry (CSP, Group Policy and
         Local Configuration) and the effective BackupDirectory value that
         decides where the password is supposed to be backed up.
      2. The legacy Microsoft LAPS footprint: the legacy Group Policy Client
         Side Extension (CSE) registration, the legacy MSI product, and the
         legacy policy registry root.
      3. The Windows LAPS Operational event log, to establish what the device
         ACTUALLY did (which directory it last backed up to, and when) versus
         what the policy says it SHOULD do.

    It then flags drift. Typical findings include: a device configured to back
    up to Microsoft Entra ID that is still running the legacy client and writing
    the legacy ms-Mcs-AdmPwd attribute in Active Directory, or two managers
    (Windows LAPS and legacy Microsoft LAPS) both trying to manage the same
    local administrator account, which Microsoft does not support.

    The script reads local state only. No Microsoft Graph, Entra ID or Active
    Directory authentication is required or performed.

.PARAMETER ExportCsv
    Also write the findings to a CSV file. Combine with -CsvPath to control the
    location. When -CsvPath is omitted a timestamped file is written to the
    current directory.

.PARAMETER CsvPath
    Full path for the CSV output file. Only used when -ExportCsv is specified.

.PARAMETER StaleGraceDays
    Extra days added on top of the effective PasswordAgeDays policy value before
    the last successful rotation is treated as stale. Default is 7.

.PARAMETER ProactiveRemediation
    Emit Intune Proactive Remediation compatible exit codes (0 = compliant,
    1 = issue found) instead of the standalone 0/1/2 scheme. See .NOTES.

.EXAMPLE
    .\Get-LapsMigrationDrift.ps1
    Runs the audit and prints a colour-coded report to the console.

.EXAMPLE
    .\Get-LapsMigrationDrift.ps1 -ExportCsv -CsvPath C:\Temp\laps-drift.csv
    Runs the audit and also writes the findings to the specified CSV file.

.EXAMPLE
    .\Get-LapsMigrationDrift.ps1 -ProactiveRemediation
    Runs the audit as an Intune Proactive Remediation DETECTION script. Exits 0
    when the device is clean, 1 when any drift or error is found.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    License: free to use and modify. Report-only. Safe to run fleet-wide.

    Standalone exit codes:
        0 = clean, no drift detected
        1 = the script itself failed (a read threw an unexpected error)
        2 = drift or misconfiguration detected

    Proactive Remediation (-ProactiveRemediation) exit codes:
        0 = compliant (no drift)
        1 = issue found, OR the script errored (any non-clean result)

    This script deliberately does NOT call Get-LapsADPassword or
    Get-LapsAADPassword (both reveal the actual password) and does NOT call
    Get-LapsDiagnostics (which writes a diagnostics bundle to disk). It stays a
    pure read with no side effects. If you want a deeper local trace, run
    Get-LapsDiagnostics yourself as an admin - it does not expose the password.

    Facts confirmed against Microsoft Learn:
      - Policy roots and BackupDirectory values (0/1/2):
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
      - Legacy emulation mode and legacy CSE detection GUID:
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy
      - Operational event log channel and event IDs:
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-event-log
      - Migration guidance and legacy MSI product code:
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-migration
#>
[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$CsvPath,
    [int]$StaleGraceDays = 7,
    [switch]$ProactiveRemediation
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

# --------------------------------------------------------------------------
# Constants - all confirmed against Microsoft Learn (see .NOTES)
# --------------------------------------------------------------------------
$LapsLogName   = 'Microsoft-Windows-LAPS/Operational'
$LegacyCseKey  = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}'
$LegacyPolRoot = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
$LegacyMsiKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{97E2CA7B-B657-4FF7-A6DB-30ECC73E1E28}',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{97E2CA7B-B657-4FF7-A6DB-30ECC73E1E28}'
)
# Windows LAPS policy roots, in the documented precedence order (top wins).
$PolicyRoots = [ordered]@{
    'CSP'   = 'HKLM:\Software\Microsoft\Policies\LAPS'
    'GPO'   = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
    'Local' = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'
}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function Write-Line {
    param([string]$Text, [string]$Colour = 'Gray')
    Write-Host $Text -ForegroundColor $Colour
}

function Get-RegValueSafe {
    param([string]$Path, [string]$Name)
    # Absence of a key or value is DATA (returns $null), not an error.
    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
    } catch {
        return $null
    }
    return $null
}

function Get-BackupDirName {
    param($Value)
    switch ($Value) {
        0       { 'Disabled (0)' }
        1       { 'Microsoft Entra ID (1)' }
        2       { 'Active Directory (2)' }
        default { '(not configured)' }
    }
}

$script:Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Severity, [string]$Check, [string]$Detail)
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Check    = $Check
        Detail   = $Detail
    })
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
$computer = $env:COMPUTERNAME
$now      = Get-Date

Write-Line ""
Write-Line "=== Windows LAPS legacy migration drift audit ===" 'Cyan'
Write-Line ("Device   : {0}" -f $computer)
Write-Line ("Run time : {0}" -f $now.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Line ("Mode     : read-only (no changes are made)")
Write-Line ""

# Values collected for the state block and CSV, initialised so they always exist.
$effectiveRoot   = $null
$effectiveBackup = $null
$effectiveAge    = $null
$legacyCse       = $false
$legacyDll       = $null
$legacyRoot      = $false
$legacyEnabled   = $null
$legacyMsi       = $false
$actualDir       = 'Unknown'
$lastRotation    = $null
$lastConfigId    = $null

try {
    # ----- 1. Windows LAPS configured intent -----------------------------
    foreach ($key in $PolicyRoots.Keys) {
        $bd = Get-RegValueSafe -Path $PolicyRoots[$key] -Name 'BackupDirectory'
        if ($null -ne $bd) {
            $effectiveRoot   = $key
            $effectiveBackup = [int]$bd
            $age = Get-RegValueSafe -Path $PolicyRoots[$key] -Name 'PasswordAgeDays'
            if ($null -ne $age) { $effectiveAge = [int]$age }
            break
        }
    }

    # ----- 2. Legacy Microsoft LAPS footprint ----------------------------
    $legacyDll = Get-RegValueSafe -Path $LegacyCseKey -Name 'DllName'
    $legacyCse = -not [string]::IsNullOrWhiteSpace($legacyDll)

    $legacyRoot = Test-Path -LiteralPath $LegacyPolRoot
    if ($legacyRoot) {
        $legacyEnabled = Get-RegValueSafe -Path $LegacyPolRoot -Name 'AdmPwdEnabled'
    }

    foreach ($mk in $LegacyMsiKeys) {
        if (Test-Path -LiteralPath $mk) { $legacyMsi = $true; break }
    }

    # ----- 3. What the device actually did (event log) -------------------
    $lapsLogPresent = $true
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $LapsLogName
            Id      = 10018, 10029, 10020, 10021, 10022, 10023, 10005
        } -ErrorAction Stop)
    } catch {
        $m = $_.Exception.Message
        if ($m -match 'No events were found') {
            $events = @()                 # channel exists, nothing matched
        } elseif ($m -match 'There is not an event log' -or $m -match 'do(es)? not exist' -or $m -match 'could not be found') {
            $lapsLogPresent = $false      # channel missing (older OS build)
        } else {
            throw                         # genuine failure - fail loud below
        }
    }

    function Get-Latest {
        param([int]$Id)
        $events | Where-Object { $_.Id -eq $Id } |
            Sort-Object TimeCreated -Descending | Select-Object -First 1
    }

    $last10018 = Get-Latest 10018   # backup to Active Directory
    $last10029 = Get-Latest 10029   # backup to Microsoft Entra ID
    $last10020 = Get-Latest 10020   # local account password updated
    $last10005 = Get-Latest 10005   # policy processing failed
    $lastConfig = $events | Where-Object { $_.Id -in 10021, 10022, 10023 } |
        Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($lastConfig) { $lastConfigId = [int]$lastConfig.Id }

    $adTime    = if ($last10018) { $last10018.TimeCreated } else { $null }
    $entraTime = if ($last10029) { $last10029.TimeCreated } else { $null }

    if ($adTime -and (-not $entraTime -or $adTime -gt $entraTime)) {
        $actualDir = 'Active Directory'
    } elseif ($entraTime -and (-not $adTime -or $entraTime -gt $adTime)) {
        $actualDir = 'Microsoft Entra ID'
    }

    $rotTimes = @()
    if ($adTime)    { $rotTimes += $adTime }
    if ($entraTime) { $rotTimes += $entraTime }
    if ($last10020) { $rotTimes += $last10020.TimeCreated }
    if ($rotTimes.Count -gt 0) {
        $lastRotation = ($rotTimes | Sort-Object -Descending | Select-Object -First 1)
    }

    # ----- State block ----------------------------------------------------
    Write-Line "--- Observed state ---" 'Cyan'
    Write-Line ("  Windows LAPS policy root (active) : {0}" -f ($(if ($effectiveRoot) { $effectiveRoot } else { 'none' })))
    Write-Line ("  Configured BackupDirectory        : {0}" -f (Get-BackupDirName $effectiveBackup))
    Write-Line ("  Effective PasswordAgeDays         : {0}" -f ($(if ($null -ne $effectiveAge) { $effectiveAge } else { 'default/unset' })))
    Write-Line ("  Legacy CSE registered             : {0}" -f $legacyCse)
    if ($legacyCse) { Write-Line ("    DllName                         : {0}" -f $legacyDll) }
    Write-Line ("  Legacy MSI installed              : {0}" -f $legacyMsi)
    Write-Line ("  Legacy policy root present        : {0}" -f $legacyRoot)
    if ($null -ne $legacyEnabled) { Write-Line ("    AdmPwdEnabled                   : {0}" -f $legacyEnabled) }
    Write-Line ("  Most recent policy-config event   : {0}" -f ($(if ($lastConfigId) { $lastConfigId } else { 'none' })))
    Write-Line ("  Actual backup directory (events)  : {0}" -f $actualDir)
    Write-Line ("  Last successful rotation          : {0}" -f ($(if ($lastRotation) { $lastRotation.ToString('yyyy-MM-dd HH:mm:ss') } else { 'not seen in log' })))
    if (-not $lapsLogPresent) { Write-Line ("  NOTE: {0} channel not found" -f $LapsLogName) 'Yellow' }
    Write-Line ""

    # ----- Drift checks ---------------------------------------------------

    # No LAPS of any kind
    if ($null -eq $effectiveBackup -and -not $legacyCse -and -not $legacyRoot -and -not $lapsLogPresent) {
        Add-Finding 'RED' 'No LAPS detected' 'No Windows LAPS policy, no legacy footprint and no LAPS event channel were found. This device does not appear to manage a local admin password at all.'
    }

    # Headline drift: two managers on the same account
    if ($legacyCse -and $null -ne $effectiveBackup -and $effectiveBackup -ne 0) {
        Add-Finding 'RED' 'Dual management' ("Legacy Microsoft LAPS CSE is still registered while a Windows LAPS policy is active (BackupDirectory={0}). Two managers can fight over the same local account; Microsoft states this is a security risk and is not supported." -f (Get-BackupDirName $effectiveBackup))
    }

    # Wrong directory: config says one place, evidence says another
    if ($effectiveBackup -eq 1 -and $actualDir -eq 'Active Directory') {
        Add-Finding 'RED' 'Wrong directory' 'Policy is configured to back up to Microsoft Entra ID (BackupDirectory=1), but the most recent successful backup event (10018) shows the password was written to Active Directory.'
    }
    if ($effectiveBackup -eq 2 -and $actualDir -eq 'Microsoft Entra ID') {
        Add-Finding 'RED' 'Wrong directory' 'Policy is configured to back up to Active Directory (BackupDirectory=2), but the most recent successful backup event (10029) shows the password was written to Microsoft Entra ID.'
    }

    # Legacy emulation mode active (event 10023)
    if ($lastConfigId -eq 10023) {
        if ($null -eq $effectiveBackup -or $effectiveBackup -eq 0) {
            Add-Finding 'AMBER' 'Legacy emulation active' 'The most recent policy event is 10023 (Legacy LAPS). The device is honouring a legacy Microsoft LAPS GPO and writing the clear-text ms-Mcs-AdmPwd attribute in Active Directory. No native Windows LAPS policy is in effect - migration is not complete on this device.'
        } else {
            Add-Finding 'RED' 'Legacy emulation active' ("Event 10023 (Legacy LAPS) is the most recent policy event even though a Windows LAPS policy is configured (BackupDirectory={0}). Investigate policy precedence on this device." -f (Get-BackupDirName $effectiveBackup))
        }
    }

    # Legacy MSI not yet uninstalled
    if ($legacyMsi) {
        Add-Finding 'AMBER' 'Legacy MSI present' 'The legacy Microsoft LAPS MSI ({97E2CA7B-B657-4FF7-A6DB-30ECC73E1E28}) is still installed. Uninstall it once the Windows LAPS transition is confirmed.'
    }

    # Legacy GPO policy root still linked
    if ($legacyRoot) {
        $enabledText = if ($null -ne $legacyEnabled) { " (AdmPwdEnabled=$legacyEnabled)" } else { "" }
        Add-Finding 'AMBER' 'Legacy policy root' ("The legacy Microsoft LAPS policy root HKLM\Software\Policies\Microsoft Services\AdmPwd is present{0}. Unlink the legacy GPO so it stops applying." -f $enabledText)
    }

    # Stale / not rotating (only meaningful when a policy is configured)
    if ($null -ne $effectiveBackup -and $effectiveBackup -ne 0) {
        $ageDays   = if ($null -ne $effectiveAge) { $effectiveAge } else { 30 }
        $threshold = $ageDays + $StaleGraceDays
        if ($lastRotation) {
            $daysSince = [math]::Round(((Get-Date) - $lastRotation).TotalDays)
            if ($daysSince -gt $threshold) {
                Add-Finding 'AMBER' 'Stale password' ("Last successful password update was {0} days ago, beyond the {1} day threshold (PasswordAgeDays {2} + grace {3}). The password may not be rotating." -f $daysSince, $threshold, $ageDays, $StaleGraceDays)
            }
        } elseif ($lapsLogPresent) {
            Add-Finding 'AMBER' 'No rotation evidence' 'A Windows LAPS policy is configured, but no successful password-update event (10018 or 10029) was found in the Operational log. The device may not have rotated yet, or the events have rolled out of the log.'
        }
    }

    # Recent policy-processing failure
    if ($last10005) {
        Add-Finding 'AMBER' 'Recent failure' ("The most recent policy-processing FAILURE event (10005) was logged at {0}. Open the Operational log for the error code." -f $last10005.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
    }

    # LAPS log channel missing
    if (-not $lapsLogPresent) {
        Add-Finding 'AMBER' 'LAPS log missing' ("The {0} channel was not found. This OS build may predate in-box Windows LAPS, so backup behaviour could not be confirmed from events." -f $LapsLogName)
    }

    # ----- Report findings ------------------------------------------------
    Write-Line "--- Findings ---" 'Cyan'
    if ($script:Findings.Count -eq 0) {
        Write-Line "  [PASS] No LAPS migration drift detected on this device." 'Green'
    } else {
        foreach ($f in $script:Findings) {
            $c = if ($f.Severity -eq 'RED') { 'Red' } else { 'Yellow' }
            Write-Line ("  [{0}] {1}: {2}" -f $f.Severity, $f.Check, $f.Detail) $c
        }
    }
    Write-Line ""
}
catch {
    $script:hadError = $true
    Write-Line ""
    Write-Line ("[FAIL] Unhandled error during audit: {0}" -f $_.Exception.Message) 'Red'
    Write-Line "[FAIL] Results are incomplete. Not reporting the device as clean." 'Red'
}

# --------------------------------------------------------------------------
# CSV export (optional)
# --------------------------------------------------------------------------
if ($ExportCsv) {
    try {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $CsvPath = Join-Path (Get-Location) ("LapsMigrationDrift_{0}_{1}.csv" -f $computer, $now.ToString('yyyyMMdd_HHmmss'))
        }
        $rows = @()
        $baseValues = @{
            ComputerName             = $computer
            Timestamp                = $now.ToString('yyyy-MM-dd HH:mm:ss')
            EffectivePolicyRoot      = $effectiveRoot
            ConfiguredBackupDir      = (Get-BackupDirName $effectiveBackup)
            ActualBackupDir          = $actualDir
            LegacyCseInstalled       = $legacyCse
            LegacyMsiInstalled       = $legacyMsi
            LegacyPolicyRootPresent  = $legacyRoot
            LastConfigEventId        = $lastConfigId
            LastRotation             = $(if ($lastRotation) { $lastRotation.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
        }
        if ($script:Findings.Count -eq 0) {
            $rows += [pscustomobject]($baseValues + @{ Severity = 'OK'; Check = 'None'; Detail = 'No drift detected' })
        } else {
            foreach ($f in $script:Findings) {
                $rows += [pscustomobject]($baseValues + @{ Severity = $f.Severity; Check = $f.Check; Detail = $f.Detail })
            }
        }
        $rows | Select-Object ComputerName, Timestamp, Severity, Check, Detail,
            EffectivePolicyRoot, ConfiguredBackupDir, ActualBackupDir,
            LegacyCseInstalled, LegacyMsiInstalled, LegacyPolicyRootPresent,
            LastConfigEventId, LastRotation |
            Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Line ("CSV exported: {0}" -f $CsvPath)
    }
    catch {
        $script:hadError = $true
        Write-Line ("[FAIL] CSV export failed: {0}" -f $_.Exception.Message) 'Red'
    }
}

# --------------------------------------------------------------------------
# Summary and exit
# --------------------------------------------------------------------------
$redCount   = @($script:Findings | Where-Object { $_.Severity -eq 'RED' }).Count
$amberCount = @($script:Findings | Where-Object { $_.Severity -eq 'AMBER' }).Count

Write-Line "--- Summary ---" 'Cyan'
Write-Line ("  RED findings   : {0}" -f $redCount)   $(if ($redCount -gt 0) { 'Red' } else { 'Green' })
Write-Line ("  AMBER findings : {0}" -f $amberCount) $(if ($amberCount -gt 0) { 'Yellow' } else { 'Green' })

if ($script:hadError) {
    Write-Line "  RESULT         : ERROR - audit did not complete." 'Red'
    exit 1
}

$hasFindings = ($script:Findings.Count -gt 0)

if ($ProactiveRemediation) {
    if ($hasFindings) {
        Write-Line "  RESULT         : ISSUE FOUND (Proactive Remediation exit 1)." 'Yellow'
        exit 1
    } else {
        Write-Line "  RESULT         : COMPLIANT (Proactive Remediation exit 0)." 'Green'
        exit 0
    }
}

if ($hasFindings) {
    Write-Line "  RESULT         : DRIFT DETECTED (exit 2)." 'Yellow'
    exit 2
} else {
    Write-Line "  RESULT         : CLEAN (exit 0)." 'Green'
    exit 0
}
