<#
.SYNOPSIS
    Read-only evidence collector for monthly Windows 11 patch QA.

.DESCRIPTION
    Collects the facts a tester needs to sign off one device after a monthly Windows 11 update:
    the exact build and whether it is on the expected revision, time since the last restart,
    whether memory integrity is running, BitLocker and Secure Boot state, the two NTLM signing
    registry values introduced on 10 November 2026, and any device reporting Code 10
    ("Device cannot start").

    It changes nothing on the device. Run it from an elevated Windows PowerShell or
    PowerShell 7 session: Microsoft documents that Confirm-SecureBootUEFI needs administrator
    rights, and a standard user may not be able to read BitLocker state either. When a check
    cannot be read, the script reports a warning or info line and says so (it never guesses).

.PARAMETER ExpectedRevision
    The revision (the number after the dot in the build) the update should leave behind.
    November 2026: 9974 for KB5132061 (the standard update), 9911 for hotpatch KB5132043.
    A revision above the target also passes, because revisions only go up.

.PARAMETER CsvPath
    Optional. Writes the results to a CSV file so they can be attached to the test record.

.EXAMPLE
    .\Get-PatchQaEvidence.ps1 -ExpectedRevision 9974

.EXAMPLE
    .\Get-PatchQaEvidence.ps1 -ExpectedRevision 9911 -CsvPath .\evidence.csv

.NOTES
    Exit code 0 = no FAIL. Exit code 1 = at least one FAIL.
    Blog post: https://endpointweekly.com/blog/kb5132061-november-2026-patch-tuesday-qa-test-plan.html
    This file is ASCII only on purpose: Windows PowerShell 5.1 misreads non-ASCII characters in
    files that have no byte order mark.
#>
[CmdletBinding()]
param(
    [int]$ExpectedRevision = 9974,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
}

# 1. Build and revision ---------------------------------------------------------------------
$cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$bld  = [string]$cv.CurrentBuildNumber
$ubr  = [int]$cv.UBR
$full = "$bld.$ubr"
if ($bld -notin '26100', '26200', '26300') {
    Add-Result 'Build' 'INFO' "$full ($($cv.DisplayVersion)) is not a 24H2, 25H2 or 26H2 build, so this month's target does not apply"
}
elseif ($ubr -ge $ExpectedRevision) {
    Add-Result 'Build' 'PASS' "$full ($($cv.DisplayVersion)) is at or above $bld.$ExpectedRevision"
}
else {
    Add-Result 'Build' 'FAIL' "$full ($($cv.DisplayVersion)) is behind $bld.$ExpectedRevision"
}

# 2. Last restart ---------------------------------------------------------------------------
$os   = Get-CimInstance -ClassName Win32_OperatingSystem
$days = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
Add-Result 'Last restart' 'INFO' "$($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')) ($days days ago)"

# 3. Virtualization-based security and memory integrity -------------------------------------
try {
    $dg   = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    $vbs  = [int]$dg.VirtualizationBasedSecurityStatus
    $hvci = @($dg.SecurityServicesRunning) -contains 2
    $vbsText = switch ($vbs) {
        0       { 'not enabled' }
        1       { 'enabled but not running' }
        2       { 'running' }
        default { "unknown value $vbs" }
    }
    if ($hvci) { Add-Result 'Memory integrity' 'INFO' "running (VBS: $vbsText). If it was off before the update, run the driver and peripheral workout" }
    else       { Add-Result 'Memory integrity' 'INFO' "not running (VBS: $vbsText)" }
}
catch {
    Add-Result 'Memory integrity' 'WARN' "could not read Win32_DeviceGuard: $($_.Exception.Message)"
}

# 4. BitLocker on the system drive ----------------------------------------------------------
try {
    $bl    = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $types = ($bl.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
    if ("$($bl.ProtectionStatus)" -eq 'On') { Add-Result 'BitLocker' 'PASS' "On for $env:SystemDrive (protectors: $types)" }
    else { Add-Result 'BitLocker' 'WARN' "ProtectionStatus is $($bl.ProtectionStatus) for $env:SystemDrive" }
}
catch {
    Add-Result 'BitLocker' 'WARN' "could not read BitLocker state (try an elevated session): $($_.Exception.Message)"
}

# 5. Secure Boot ----------------------------------------------------------------------------
try {
    if (Confirm-SecureBootUEFI) { Add-Result 'Secure Boot' 'PASS' 'enabled' }
    else { Add-Result 'Secure Boot' 'WARN' 'supported but disabled' }
}
catch {
    Add-Result 'Secure Boot' 'INFO' "not readable here (BIOS mode, no support, or not elevated): $($_.Exception.Message)"
}

# 6. NTLM signing values added by the 10 November 2026 updates (Microsoft KB5135557) ---------
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$clientVal = (Get-ItemProperty -Path $msv -Name 'ClientAllowUnsignedNtlm' -ErrorAction SilentlyContinue).ClientAllowUnsignedNtlm
if ($null -eq $clientVal)    { Add-Result 'NTLM ClientAllowUnsignedNtlm' 'INFO' 'not set (default 0: this client offers signing)' }
elseif ([int]$clientVal -eq 1) { Add-Result 'NTLM ClientAllowUnsignedNtlm' 'WARN' 'set to 1: this client does NOT offer signing (temporary compatibility only)' }
else                         { Add-Result 'NTLM ClientAllowUnsignedNtlm' 'INFO' "set to $clientVal" }

$serverVal = (Get-ItemProperty -Path $msv -Name 'ServerRequireNtlmSign' -ErrorAction SilentlyContinue).ServerRequireNtlmSign
if ($null -eq $serverVal)    { Add-Result 'NTLM ServerRequireNtlmSign' 'INFO' 'not set (default 0: unsigned clients are still accepted)' }
elseif ([int]$serverVal -eq 1) { Add-Result 'NTLM ServerRequireNtlmSign' 'INFO' 'set to 1: this server rejects unsigned NTLM clients' }
else                         { Add-Result 'NTLM ServerRequireNtlmSign' 'INFO' "set to $serverVal" }

# 7. Devices that cannot start (Code 10), for example USB audio -----------------------------
$bad = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode = 10')
if ($bad.Count -eq 0) {
    Add-Result 'Devices with Code 10' 'PASS' 'none'
}
else {
    $names = ($bad | ForEach-Object { "$($_.Name) [$($_.PNPClass)]" }) -join '; '
    Add-Result 'Devices with Code 10' 'WARN' "$($bad.Count): $names"
}

# Output ------------------------------------------------------------------------------------
$results | Format-Table Check, Status, Detail -AutoSize -Wrap
if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    "Saved: $CsvPath"
}
if (@($results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { exit 1 } else { exit 0 }
