<#
.SYNOPSIS
    Proves, on the device itself, whether Intune actually delivered and applied the
    Windows Hello for Business policy - rather than trusting the Intune console.

.DESCRIPTION
    Windows Hello for Business does NOT write its policy to the usual
    PolicyManager\current\device\<AreaName> location that most Intune CSP policies use.
    It writes to a tenant-GUID-scoped path instead:

        HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies

    That single fact causes a lot of false "the policy did not apply" conclusions, because
    admins look in PolicyManager, find nothing, and assume delivery failed.

    This script checks every layer in order of authority:
      1. MDM enrollment state          - is the device even talking to Intune
      2. Delivered WHfB policy         - the tenant-scoped PassportForWork key
      3. Related CredentialProviders   - AllowPINLogon lands somewhere different again
      4. Group Policy WHfB keys        - a competing source that can override MDM
      5. MDM diagnostic events         - did the last sync actually succeed
      6. Runtime WHfB state            - dsregcmd, the proof Hello is genuinely usable

    READ-ONLY. The script makes no changes to the device. It writes a single report file
    to the Desktop (or to -OutputPath) and prints the same content to the console.

.PARAMETER OutputPath
    Full path for the report file. Defaults to a timestamped file on the current user's Desktop.

.PARAMETER FullReport
    Also runs MdmDiagnosticsTool.exe to produce Microsoft's own MDMDiagReport.html, which
    lists every policy delivered over the MDM channel. Requires elevation.

.PARAMETER Quiet
    Suppresses console output. The report file is still written.

.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File .\Get-WHfBPolicyOnDevice.ps1

    Runs all checks and saves a report to the Desktop.

.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File .\Get-WHfBPolicyOnDevice.ps1 -FullReport

    As above, plus generates Microsoft's full MDM diagnostic report. Run elevated.

.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File .\Get-WHfBPolicyOnDevice.ps1 -OutputPath C:\Temp\whfb.txt -Quiet

    Writes the report to a specific path with no console output, for collection at scale.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks

    Read-only. No changes are made to the device.
    Exit codes: 0 = checks completed, 2 = a check could not be run.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$FullReport,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$script:hadError = $false

if (-not $OutputPath) {
    $desktop    = [Environment]::GetFolderPath('Desktop')
    $OutputPath = Join-Path $desktop ("WHfB-PolicyCheck-{0}.txt" -f (Get-Date -Format 'yyyy-MM-dd_HHmm'))
}

$report = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$Text) $report.Add($Text) }
function Add-Section {
    param([string]$Title)
    Add-Line ''
    Add-Line ('=' * 78)
    Add-Line $Title
    Add-Line ('=' * 78)
}

Add-Line ("Windows Hello for Business - policy delivery check")
Add-Line ("Generated : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-Line ("Computer  : {0}" -f $env:COMPUTERNAME)
Add-Line ("User      : {0}" -f $env:USERNAME)
Add-Line ("Mode      : READ-ONLY. No settings changed.")

# ---------------------------------------------------------------- 1. Enrollment
Add-Section 'CHECK 1 - MDM enrollment state'
$enrollmentId = $null
try {
    $enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (Test-Path $enrollRoot) {
        foreach ($k in (Get-ChildItem $enrollRoot -ErrorAction Stop)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            # A real enrollment has a UPN or a discovery URL. The rest are placeholder keys.
            if ($p.UPN -or $p.DiscoveryServiceFullURL) {
                $enrollmentId = $k.PSChildName
                Add-Line ("  Enrollment GUID    : {0}" -f $k.PSChildName)
                Add-Line ("  UPN                : {0}" -f $p.UPN)
                Add-Line ("  Discovery URL      : {0}" -f $p.DiscoveryServiceFullURL)
                Add-Line ("  Provider ID        : {0}" -f $p.ProviderID)
                Add-Line ("  EnrollmentState    : {0}  (1 = enrolled)" -f $p.EnrollmentState)
                Add-Line ("  EnrollmentType     : {0}" -f $p.EnrollmentType)
                Add-Line ''
            }
        }
    }
    if (-not $enrollmentId) {
        Add-Line '  No active MDM enrollment found. Intune policy cannot reach this device.'
    }
}
catch {
    $script:hadError = $true
    Add-Line ("  Could not read enrollment state: {0}" -f $_.Exception.Message)
}

# ---------------------------------------------------------------- 2. Delivered WHfB policy
Add-Section 'CHECK 2 - WHfB policy delivered by Intune (tenant-scoped PassportForWork key)'
Add-Line '  Path: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies'
Add-Line ''
$whfbBase  = 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork'
$whfbFound = $false
if (Test-Path $whfbBase) {
    $keys = @(Get-Item $whfbBase) + @(Get-ChildItem $whfbBase -Recurse -ErrorAction SilentlyContinue)
    foreach ($k in $keys) {
        $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $names = $item.GetValueNames()
        if (-not $names) { continue }
        $whfbFound = $true
        $shortPath = $item.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Policies\\', ''
        Add-Line ("  [{0}]" -f $shortPath)
        foreach ($n in ($names | Sort-Object)) {
            Add-Line ("      {0,-44} = {1}" -f $n, $item.GetValue($n))
        }
        Add-Line ''
    }
    if (-not $whfbFound) {
        Add-Line '  Key exists but holds no values. Nothing was delivered.'
    }
}
else {
    Add-Line '  Key does not exist. Intune has NOT delivered any WHfB policy to this device.'
}

# ---------------------------------------------------------------- 3. CredentialProviders
Add-Section 'CHECK 3 - Related CredentialProviders policy (AllowPINLogon lands here, not above)'
Add-Line '  AllowPINLogon is commonly set in the same Intune policy as the WHfB settings,'
Add-Line '  but it is a different CSP and is stored in a different place entirely.'
Add-Line ''
$cpCurrent = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialProviders'
if (Test-Path $cpCurrent) {
    $item = Get-Item $cpCurrent
    Add-Line ("  [{0}]" -f ($item.Name -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\'))
    foreach ($n in ($item.GetValueNames() | Sort-Object)) {
        Add-Line ("      {0,-44} = {1}" -f $n, $item.GetValue($n))
    }
    Add-Line ''
    Add-Line '  A _WinningProvider value naming an enrollment GUID means MDM won this setting.'
}
else {
    Add-Line '  No CredentialProviders policy present.'
}

Add-Line ''
Add-Line '  Provider-level value (the raw delivered state):'
$anyProvider = $false
try {
    $provRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
    if (Test-Path $provRoot) {
        foreach ($k in (Get-ChildItem $provRoot -Recurse -ErrorAction SilentlyContinue)) {
            $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($n in $item.GetValueNames()) {
                if ($n -like '*PINLogon*') {
                    $anyProvider = $true
                    Add-Line ("      {0}\{1} = {2}" -f ($item.Name -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\'), $n, $item.GetValue($n))
                }
            }
        }
    }
}
catch { $script:hadError = $true }
if (-not $anyProvider) { Add-Line '      (none found)' }

Add-Line ''
Add-Line '  Resulting effective value:'
$sysPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
if (Test-Path $sysPol) {
    $item = Get-Item $sysPol
    foreach ($n in ($item.GetValueNames() | Sort-Object)) {
        if ($n -match 'PINLogon|PicturePassword') {
            Add-Line ("      {0,-44} = {1}" -f $n, $item.GetValue($n))
        }
    }
}
else { Add-Line '      (none found)' }

# ---------------------------------------------------------------- 4. GPO conflict
Add-Section 'CHECK 4 - Group Policy WHfB keys (a competing source - GPO can override MDM)'
$gpoBase = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
if (Test-Path $gpoBase) {
    Add-Line '  GPO-based WHfB policy IS present on this device.'
    Add-Line '  If a value here disagrees with the Intune value in CHECK 2, GPO normally wins.'
    Add-Line ''
    $keys = @(Get-Item $gpoBase) + @(Get-ChildItem $gpoBase -Recurse -ErrorAction SilentlyContinue)
    foreach ($k in $keys) {
        $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($n in ($item.GetValueNames() | Sort-Object)) {
            $shortPath = $item.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\', ''
            Add-Line ("      {0}\{1} = {2}" -f $shortPath, $n, $item.GetValue($n))
        }
    }
}
else {
    Add-Line '  No GPO WHfB policy present. No conflict with Intune.'
}

# ---------------------------------------------------------------- 5. MDM events
Add-Section 'CHECK 5 - MDM diagnostic events (last 7 days)'
$mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
Add-Line ("  Channel: {0}" -f $mdmLog)
Add-Line ''
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $mdmLog; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop
    Add-Line ("  Total events: {0}" -f @($ev).Count)
    Add-Line ''
    Add-Line '  Event ID summary (most frequent first):'
    foreach ($g in ($ev | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 15)) {
        Add-Line ("      ID={0,-8} count={1}" -f $g.Name, $g.Count)
    }
    Add-Line ''
    Add-Line '  Most recent errors and warnings:'
    $bad = $ev | Where-Object { $_.LevelDisplayName -in @('Error', 'Warning') } |
        Sort-Object TimeCreated -Descending | Select-Object -First 12
    if ($bad) {
        foreach ($e in $bad) {
            $first = ($e.Message -split "`r?`n")[0]
            Add-Line ("      {0}  ID={1,-6} {2,-8} {3}" -f $e.TimeCreated, $e.Id, $e.LevelDisplayName, $first)
        }
    }
    else { Add-Line '      None. Every MDM event in the window was informational.' }
}
catch {
    $script:hadError = $true
    Add-Line ("  Could not read the MDM event channel: {0}" -f $_.Exception.Message)
}

# ---------------------------------------------------------------- 6. Runtime state
Add-Section 'CHECK 6 - Runtime WHfB state (dsregcmd)'
try {
    $ds = dsregcmd /status
    $wanted = 'AzureAdJoined|DomainJoined|WorkplaceJoined|DeviceAuthStatus|TpmProtected|MdmUrl|NgcSet|NgcKeyId|AzureAdPrt\s|OnPremTgt|CloudTgt|KeySignTest'
    foreach ($line in ($ds | Where-Object { $_ -match $wanted })) {
        Add-Line ("  {0}" -f $line.Trim())
    }
    Add-Line ''
    Add-Line '  NgcSet = YES is the proof that Hello is genuinely provisioned for this user.'
    Add-Line '  Policy can be delivered correctly and NgcSet still be NO if the user has not enrolled.'
}
catch {
    $script:hadError = $true
    Add-Line ("  dsregcmd failed: {0}" -f $_.Exception.Message)
}

# ---------------------------------------------------------------- 7. Optional full report
Add-Section 'CHECK 7 - MdmDiagnosticsTool full report'
if ($FullReport) {
    $outDir = Join-Path ([IO.Path]::GetDirectoryName($OutputPath)) ("MDMDiag-{0}" -f (Get-Date -Format 'yyyy-MM-dd_HHmm'))
    try {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $tool = Join-Path $env:SystemRoot 'System32\MdmDiagnosticsTool.exe'
        $proc = Start-Process -FilePath $tool -ArgumentList ('-out "{0}"' -f $outDir) -Wait -PassThru -NoNewWindow
        Add-Line ("  Exit code     : {0}" -f $proc.ExitCode)
        Add-Line ("  Report folder : {0}" -f $outDir)
        Add-Line '  Open MDMDiagReport.html there. It lists every policy delivered over MDM.'
    }
    catch {
        $script:hadError = $true
        Add-Line ("  MdmDiagnosticsTool failed (it usually needs elevation): {0}" -f $_.Exception.Message)
    }
}
else {
    Add-Line '  Skipped. Re-run with -FullReport to generate MDMDiagReport.html (needs elevation).'
}

# ---------------------------------------------------------------- How to read it
Add-Section 'HOW TO READ THIS REPORT'
Add-Line '  CHECK 2 empty                      -> Intune never delivered WHfB policy here.'
Add-Line '  CHECK 2 populated                  -> policy WAS delivered, regardless of console state.'
Add-Line '  CHECK 4 disagrees with CHECK 2     -> GPO is fighting Intune. GPO normally wins.'
Add-Line '  CHECK 5 shows repeated 404 / errors -> sync is failing, policy may be stale.'
Add-Line '  CHECK 6 NgcSet = YES               -> Hello is provisioned and usable.'
Add-Line ''
Add-Line '  Note: there is deliberately no PolicyManager\current\device\PassportForWork check.'
Add-Line '  WHfB does not populate that path. Its absence is normal and is not a failure.'

Add-Section 'END'
Add-Line ("Report file: {0}" -f $OutputPath)

try {
    $report | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
}
catch {
    $script:hadError = $true
    Write-Warning ("Could not write report to {0}: {1}" -f $OutputPath, $_.Exception.Message)
}

if (-not $Quiet) { $report | ForEach-Object { Write-Host $_ } }

if (-not $Quiet) {
    Write-Host ''
    Write-Host ("Report saved to: {0}" -f $OutputPath) -ForegroundColor Green
}

if ($script:hadError) { exit 2 } else { exit 0 }
