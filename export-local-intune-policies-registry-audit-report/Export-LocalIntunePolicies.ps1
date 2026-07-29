<#
.SYNOPSIS
    Reads and exports all Intune MDM policies stored locally on this machine.

.DESCRIPTION
    Reads policy data from the local registry (no internet or Graph API needed).
    Exports to a self-contained HTML report and a plain-text summary.
    Works on any Intune-enrolled Windows 10/11 device.

.PARAMETER OutputPath
    Folder for the export. Default: C:\IntuneLocalExport

.EXAMPLE
    .\Export-LocalIntunePolicies.ps1

.EXAMPLE
    .\Export-LocalIntunePolicies.ps1 -OutputPath "D:\Reports"
#>

[CmdletBinding()]
param (
    [string]$OutputPath = 'C:\IntuneLocalExport'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Logging -----------------------------------------------------------

$LogDir  = 'C:\ProgramData\Export-LocalIntunePolicies'
$LogFile = Join-Path $LogDir ('Export-LocalIntunePolicies_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO','OK','WARN','FAIL','ACTION','SECTION','RESULT')]
        [string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogFile -Value "[$ts] [$Level] $Message"
    switch ($Level) {
        'SECTION' { Write-Host "`n=== $Message ===" -ForegroundColor Cyan }
        'OK'      { Write-Host "  [OK]   $Message"  -ForegroundColor Green }
        'WARN'    { Write-Host "  [WARN] $Message"  -ForegroundColor Yellow }
        'FAIL'    { Write-Host "  [FAIL] $Message"  -ForegroundColor Red }
        'ACTION'  { Write-Host "  [-->]  $Message"  -ForegroundColor Magenta }
        'RESULT'  { Write-Host "  [RES]  $Message"  -ForegroundColor White }
        default   { Write-Host "  [INF]  $Message"  -ForegroundColor Gray }
    }
}

#endregion

#region --- Output folder -----------------------------------------------------

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportDir = Join-Path $OutputPath $timestamp
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
Write-Log 'Starting local Intune policy export' 'SECTION'
Write-Log "Output folder: $exportDir" 'INFO'

#endregion

#region --- Read registry helpers ---------------------------------------------

function Read-RegistryTree {
    param ([string]$Path)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    if (-not (Test-Path $Path)) { return $results }

    try {
        $subkeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        foreach ($key in $subkeys) {
            $area   = $key.PSChildName
            $values = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $values) { continue }

            $props = $values.PSObject.Properties |
                     Where-Object { $_.Name -notlike 'PS*' }

            foreach ($prop in $props) {
                $results.Add(@{
                    Area  = $area
                    Name  = $prop.Name
                    Value = if ($null -eq $prop.Value) { '(null)' } else { "$($prop.Value)" }
                })
            }
        }
    }
    catch {
        Write-Log "Warning reading $Path : $_" 'WARN'
    }
    return $results
}

function Read-FlatRegistry {
    param ([string]$Path)
    $results = [System.Collections.Generic.List[hashtable]]::new()
    if (-not (Test-Path $Path)) { return $results }

    try {
        $subkeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        foreach ($key in $subkeys) {
            $values = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $values) { continue }
            $props = $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
            foreach ($prop in $props) {
                $results.Add(@{
                    Key   = $key.PSChildName
                    Name  = $prop.Name
                    Value = if ($null -eq $prop.Value) { '(null)' } else { "$($prop.Value)" }
                })
            }
        }
    }
    catch {
        Write-Log "Warning reading $Path : $_" 'WARN'
    }
    return $results
}

#endregion

#region --- 1. MDM Device Policies -------------------------------------------

Write-Log 'Reading MDM device policies' 'ACTION'
$devicePolicies = @(Read-RegistryTree -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device')
Write-Log "Device policies: $($devicePolicies.Count) values found" 'OK'

#endregion

#region --- 2. MDM User Policies ----------------------------------------------

Write-Log 'Reading MDM user policies' 'ACTION'
$userPolicies = @(Read-RegistryTree -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\user')
Write-Log "User policies: $($userPolicies.Count) values found" 'OK'

#endregion

#region --- 3. MDM Provider / Enrollment Info ---------------------------------

Write-Log 'Reading MDM provider info' 'ACTION'

$providerInfoList = [System.Collections.Generic.List[hashtable]]::new()
$providerRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
if (Test-Path $providerRoot) {
    $providers = Get-ChildItem -Path $providerRoot -ErrorAction SilentlyContinue
    foreach ($prov in $providers) {
        $vals = Get-ItemProperty -Path $prov.PSPath -ErrorAction SilentlyContinue
        if ($vals) {
            $props = $vals.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
            foreach ($p in $props) {
                $providerInfoList.Add(@{
                    Provider = $prov.PSChildName
                    Name     = $p.Name
                    Value    = if ($null -eq $p.Value) { '(null)' } else { "$($p.Value)" }
                })
            }
        }
    }
}
$providerInfo = @($providerInfoList)
Write-Log "Provider info: $($providerInfo.Count) values found" 'OK'

#endregion

#region --- 4. Enrollment Details ---------------------------------------------

Write-Log 'Reading enrollment details' 'ACTION'

$enrollmentInfoList = [System.Collections.Generic.List[hashtable]]::new()
$enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
if (Test-Path $enrollRoot) {
    $enrollments = Get-ChildItem -Path $enrollRoot -ErrorAction SilentlyContinue
    foreach ($enroll in $enrollments) {
        $vals = Get-ItemProperty -Path $enroll.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $vals) { continue }
        $props = $vals.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
        foreach ($p in $props) {
            $enrollmentInfoList.Add(@{
                EnrollmentId = $enroll.PSChildName
                Name         = $p.Name
                Value        = if ($null -eq $p.Value) { '(null)' } else { "$($p.Value)" }
            })
        }
    }
}
$enrollmentInfo = @($enrollmentInfoList)
Write-Log "Enrollment info: $($enrollmentInfo.Count) values found" 'OK'

#endregion

#region --- 5. Applied Policies (HKLM\SOFTWARE\Policies\Microsoft) -----------

Write-Log 'Reading applied policies (HKLM\SOFTWARE\Policies\Microsoft)' 'ACTION'
$appliedPolicies = @(Read-RegistryTree -Path 'HKLM:\SOFTWARE\Policies\Microsoft')
Write-Log "Applied policies: $($appliedPolicies.Count) values found" 'OK'

#endregion

#region --- 6. Device join state (dsregcmd) -----------------------------------

Write-Log 'Reading device join state' 'ACTION'

$dsregRaw = & dsregcmd.exe /status 2>&1
$dsregInfoList = [System.Collections.Generic.List[hashtable]]::new()
$currentSection = 'General'

foreach ($line in $dsregRaw) {
    if ($line -match '^\s*[-|+]{3,}') { continue }
    if ($line -match '^\s*\[\s*(.+?)\s*\]') {
        $currentSection = $Matches[1]
        continue
    }
    if ($line -match '^\s*([^:]+?)\s*:\s*(.*)$') {
        $dsregInfoList.Add(@{
            Section = $currentSection
            Name    = $Matches[1].Trim()
            Value   = $Matches[2].Trim()
        })
    }
}
$dsregInfo = @($dsregInfoList)
Write-Log "Device state: $($dsregInfo.Count) values found" 'OK'

#endregion

#region --- HTML helpers ------------------------------------------------------

Add-Type -AssemblyName System.Web

function Html-Encode { param([string]$s); [System.Web.HttpUtility]::HtmlEncode($s) }

function Build-Table2Col {
    param (
        [array]$Rows,
        [string]$Col1, [string]$Col2, [string]$Col3,
        [string]$Key1, [string]$Key2, [string]$Key3
    )
    if ($Rows.Count -eq 0) { return '<p class="empty">No data found.</p>' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    [void]$sb.Append("<th class=`"col-a`">$Col1</th><th class=`"col-b`">$Col2</th><th class=`"col-c`">$Col3</th>")
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        $v1 = Html-Encode "$($row[$Key1])"
        $v2 = Html-Encode "$($row[$Key2])"
        $v3 = Html-Encode "$($row[$Key3])"
        [void]$sb.Append("<tr><td class=`"col-a`">$v1</td><td class=`"col-b`">$v2</td><td class=`"col-c val`">$v3</td></tr>")
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Build-Section {
    param ([string]$Title, [string]$CountLabel, [string]$TableHtml, [string]$Id)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<section id=`"$Id`">")
    [void]$sb.Append("<h2>$(Html-Encode $Title) <span class=`"badge`">$CountLabel</span></h2>")
    [void]$sb.Append("<div class=`"table-wrap`">$TableHtml</div>")
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

$css = @'
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f4f6f8;color:#1d2025;font-size:13px}
header{background:#1a1a2e;color:#fff;padding:24px 40px}
header h1{font-size:20px;font-weight:600}
header h1 span{color:#00a651}
.meta{margin-top:8px;font-size:12px;color:#aab0bb;display:flex;gap:24px;flex-wrap:wrap}
.meta strong{color:#e0e4ea}
.stats{background:#2d2d44;display:flex;padding:14px 40px;gap:40px;flex-wrap:wrap}
.stat .num{font-size:26px;font-weight:700;color:#00a651}
.stat .lbl{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#9ca3af}
nav{background:#fff;border-bottom:1px solid #dde2e8;padding:10px 40px;display:flex;gap:16px;flex-wrap:wrap;font-size:12px;position:sticky;top:0;z-index:10}
nav a{color:#00a651;text-decoration:none;font-weight:500}
nav a:hover{text-decoration:underline}
main{max-width:1600px;margin:24px auto;padding:0 24px}
section{background:#fff;border:1px solid #dde2e8;border-radius:8px;margin-bottom:20px;overflow:hidden}
section h2{padding:12px 20px;background:#f9fafb;border-bottom:1px solid #dde2e8;font-size:14px;font-weight:600;display:flex;align-items:center;gap:10px}
.badge{background:#00a651;color:#fff;border-radius:12px;padding:2px 10px;font-size:11px;font-weight:700}
.table-wrap{overflow-x:auto;width:100%}
table{width:100%;border-collapse:collapse;table-layout:fixed}
thead tr{background:#f1f5f9}
th{padding:10px 16px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#6b7280;font-weight:600;border-bottom:1px solid #dde2e8;white-space:nowrap}
td{padding:9px 16px;border-bottom:1px solid #f0f2f5;vertical-align:middle;overflow-wrap:break-word;word-break:break-word}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.col-a{width:22%}
.col-b{width:38%}
.col-c{width:40%}
.val{font-family:Consolas,monospace;font-size:12px;color:#374151;background:#f8fafc;padding:2px 6px;border-radius:3px;display:inline-block;max-width:100%;overflow-wrap:break-word;word-break:break-word}
.empty{padding:14px 20px;color:#6b7280;font-style:italic}
footer{text-align:center;padding:20px;font-size:11px;color:#6b7280}
'@

#endregion

#region --- Build HTML report -------------------------------------------------

Write-Log 'Generating HTML report...' 'ACTION'

$exportDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$computerName = $env:COMPUTERNAME
$currentUser  = $env:USERNAME

$s1 = Build-Section -Id 'device-policies' -Title 'MDM Device Policies (PolicyManager\current\device)' `
      -CountLabel "$($devicePolicies.Count)" `
      -TableHtml (Build-Table2Col -Rows $devicePolicies -Col1 'Area' -Col2 'Policy Name' -Col3 'Value' -Key1 'Area' -Key2 'Name' -Key3 'Value')

$s2 = Build-Section -Id 'user-policies' -Title 'MDM User Policies (PolicyManager\current\user)' `
      -CountLabel "$($userPolicies.Count)" `
      -TableHtml (Build-Table2Col -Rows $userPolicies -Col1 'Area' -Col2 'Policy Name' -Col3 'Value' -Key1 'Area' -Key2 'Name' -Key3 'Value')

$s3 = Build-Section -Id 'provider' -Title 'MDM Provider Info' `
      -CountLabel "$($providerInfo.Count)" `
      -TableHtml (Build-Table2Col -Rows $providerInfo -Col1 'Provider' -Col2 'Name' -Col3 'Value' -Key1 'Provider' -Key2 'Name' -Key3 'Value')

$s4 = Build-Section -Id 'enrollment' -Title 'Enrollment Details' `
      -CountLabel "$($enrollmentInfo.Count)" `
      -TableHtml (Build-Table2Col -Rows $enrollmentInfo -Col1 'Enrollment ID' -Col2 'Name' -Col3 'Value' -Key1 'EnrollmentId' -Key2 'Name' -Key3 'Value')

$s5 = Build-Section -Id 'applied' -Title 'Applied Policies (HKLM\SOFTWARE\Policies\Microsoft)' `
      -CountLabel "$($appliedPolicies.Count)" `
      -TableHtml (Build-Table2Col -Rows $appliedPolicies -Col1 'Area' -Col2 'Policy Name' -Col3 'Value' -Key1 'Area' -Key2 'Name' -Key3 'Value')

$s6 = Build-Section -Id 'dsreg' -Title 'Device Join State (dsregcmd)' `
      -CountLabel "$($dsregInfo.Count)" `
      -TableHtml (Build-Table2Col -Rows $dsregInfo -Col1 'Section' -Col2 'Name' -Col3 'Value' -Key1 'Section' -Key2 'Name' -Key3 'Value')

$totalValues = $devicePolicies.Count + $userPolicies.Count + $appliedPolicies.Count +
               $providerInfo.Count + $enrollmentInfo.Count + $dsregInfo.Count

$html = [System.Text.StringBuilder]::new()
[void]$html.Append('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">')
[void]$html.Append("<title>Local Intune Policies - $computerName</title>")
[void]$html.Append("<style>$css</style></head><body>")
[void]$html.Append('<header>')
[void]$html.Append("<h1>Local Intune Policies &mdash; <span>$computerName</span></h1>")
[void]$html.Append('<div class="meta">')
[void]$html.Append("<div><strong>User:</strong> $(Html-Encode $currentUser)</div>")
[void]$html.Append("<div><strong>Exported:</strong> $exportDate</div>")
[void]$html.Append('</div></header>')
[void]$html.Append('<div class="stats">')
[void]$html.Append('<div class="stat"><div class="num">6</div><div class="lbl">Data Sources</div></div>')
[void]$html.Append("<div class=`"stat`"><div class=`"num`">$totalValues</div><div class=`"lbl`">Total Values</div></div>")
[void]$html.Append('</div>')
[void]$html.Append('<nav>')
[void]$html.Append('<a href="#device-policies">Device Policies</a>')
[void]$html.Append('<a href="#user-policies">User Policies</a>')
[void]$html.Append('<a href="#provider">MDM Provider</a>')
[void]$html.Append('<a href="#enrollment">Enrollment</a>')
[void]$html.Append('<a href="#applied">Applied Policies</a>')
[void]$html.Append('<a href="#dsreg">Device State</a>')
[void]$html.Append('</nav>')
[void]$html.Append("<main>$s1$s2$s3$s4$s5$s6</main>")
[void]$html.Append("<footer>Generated by Export-LocalIntunePolicies.ps1 &nbsp;|&nbsp; $exportDate</footer>")
[void]$html.Append('</body></html>')

$htmlPath = Join-Path $exportDir 'LocalIntunePolicies_Report.html'
$html.ToString() | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
Write-Log "HTML report saved: $htmlPath" 'OK'

#endregion

#region --- Summary text file -------------------------------------------------

$lines = @(
    'Local Intune Policy Export',
    '==========================',
    "Computer : $computerName",
    "User     : $currentUser",
    "Exported : $exportDate",
    "Folder   : $exportDir",
    '',
    ("  {0,-45} {1,6} values" -f 'MDM Device Policies',                  $devicePolicies.Count),
    ("  {0,-45} {1,6} values" -f 'MDM User Policies',                    $userPolicies.Count),
    ("  {0,-45} {1,6} values" -f 'MDM Provider Info',                    $providerInfo.Count),
    ("  {0,-45} {1,6} values" -f 'Enrollment Details',                   $enrollmentInfo.Count),
    ("  {0,-45} {1,6} values" -f 'Applied Policies (SOFTWARE\Policies)', $appliedPolicies.Count),
    ("  {0,-45} {1,6} values" -f 'Device Join State (dsregcmd)',         $dsregInfo.Count),
    '',
    ("  TOTAL: $totalValues values across 6 data sources")
)
$lines | Out-File -FilePath (Join-Path $exportDir '_Summary.txt') -Encoding UTF8 -Force

#endregion

#region --- Finish ------------------------------------------------------------

Write-Log 'Export complete' 'SECTION'
Write-Log "HTML report : $htmlPath" 'RESULT'
Write-Log "Log file    : $LogFile" 'RESULT'

Write-Host "`nOpening report in browser..." -ForegroundColor Cyan
Start-Process $htmlPath

#endregion
