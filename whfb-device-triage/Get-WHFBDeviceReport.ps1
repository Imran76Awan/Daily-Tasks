<#
.SYNOPSIS
    Collects every Windows Hello for Business signal from ONE device and writes a JSON report.

.DESCRIPTION
    Windows Hello for Business health is spread across eight separate surfaces: dsregcmd, the TPM,
    the NGC container folder, the device registration certificate, PassportForWork policy, four
    Windows services, three event logs, and the audit policy. Checking one of them (usually NgcSet)
    and stopping is the single most common triage mistake, because NgcSet=YES only means a key
    exists - it does not mean the person can use it, or that they ever do.

    This script reads all of them in one pass, scores a verdict, prints a console summary, and
    writes a JSON file you can open in whfb-device-report.html (the offline viewer that ships
    beside this script).

    READ-ONLY. It reads registry, certificates, services, event logs, dsregcmd, Get-Tpm and
    auditpol. The ONLY thing it writes is the JSON report. It changes nothing on the device,
    nothing in Intune, and nothing in Entra ID. Nothing is uploaded anywhere.

    PRIVACY: the JSON contains user principal names and sign-in history for this device. Treat it
    as you would any other support capture. Use -Anonymise to mask user names and device
    identifiers before sharing it outside your team.

.PARAMETER Days
    How many days of sign-in history to summarise. Default 30.

.PARAMETER JsonPath
    Where to write the report. Defaults to a timestamped file beside the script.

.PARAMETER Anonymise
    Masks user principal names, the device ID, the NGC key ID and certificate thumbprints in the
    JSON and the console output. Use this before sending a report to a vendor or a forum.

.PARAMETER Quiet
    Suppresses the console summary and only writes the JSON.

.EXAMPLE
    .\Get-WHFBDeviceReport.ps1
    Collects the report with defaults and writes the JSON beside the script.

.EXAMPLE
    .\Get-WHFBDeviceReport.ps1 -Anonymise -JsonPath C:\Temp\device.json
    Collects a masked report that is safe to attach to a support case.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/whfb-device-triage-report-offline-viewer.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks
    Run as : Administrator (the Security log, Get-Tpm and auditpol need it; without admin the
             script still runs and tells you which sections are degraded)
    Tested : Windows 11 23H2/24H2, Windows PowerShell 5.1 and PowerShell 7
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$Days = 30,
    [string]$JsonPath = '',
    [switch]$Anonymise,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'

# $PSScriptRoot is empty inside a param() default on some hosts, so the path is built here.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $here) { $here = (Get-Location).Path }
if (-not $JsonPath) {
    $JsonPath = Join-Path $here ("WHFB-Device-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not elevated. The Security log, TPM state and audit policy cannot be read. Those sections will say so rather than guess.'
}

$sections = New-Object System.Collections.Generic.List[object]
$degraded = New-Object System.Collections.Generic.List[string]

function New-Row([string]$Key, $Value, [string]$State) {
    [pscustomobject]@{ k = "$Key"; v = "$Value"; state = "$State" }
}
function Add-KvSection([string]$Title, $Rows) {
    $sections.Add([pscustomobject]@{ title = $Title; type = 'kv'; rows = @($Rows) })
}
function Add-TableSection([string]$Title, $Headers, $Rows) {
    $sections.Add([pscustomobject]@{ title = $Title; type = 'table'; headers = @($Headers); rows = @($Rows) })
}
function Hide-Value([string]$Text) {
    if (-not $Anonymise) { return $Text }
    if (-not $Text) { return $Text }
    return '<masked>'
}
function Hide-Upn([string]$Upn) {
    if (-not $Anonymise) { return $Upn }
    if ($Upn -match '^([^@]+)@(.+)$') {
        $name = $Matches[1]
        $keep = $name.Substring(0, [Math]::Min(2, $name.Length))
        return ('{0}***@{1}' -f $keep, '<domain>')
    }
    return '<masked>'
}

# ---------------------------------------------------------------- dsregcmd
# Field names are matched with [ \t] rather than \s, because \s also matches a newline and an
# empty field would then swallow the value from the following line.
$dsregText = ''
try { $dsregText = (dsregcmd /status) -join "`n" } catch { $degraded.Add('dsregcmd could not be run') }
function Get-DsregField([string]$Name) {
    if ($dsregText -match "(?m)^[ \t]*$Name[ \t]*:[ \t]*(.*)$") { return $Matches[1].TrimEnd() }
    return ''
}

$aadJoined  = Get-DsregField 'AzureAdJoined'
$domJoined  = Get-DsregField 'DomainJoined'
$ngcSet     = Get-DsregField 'NgcSet'
$prt        = Get-DsregField 'AzureAdPrt'
$prtExpiry  = Get-DsregField 'AzureAdPrtExpiryTime'
$prtUpdate  = Get-DsregField 'AzureAdPrtUpdateTime'
$onPremTgt  = Get-DsregField 'OnPremTgt'
$cloudTgt   = Get-DsregField 'CloudTgt'
$tpmProt    = Get-DsregField 'TpmProtected'
$keyProv    = Get-DsregField 'KeyProvider'
$devAuth    = Get-DsregField 'DeviceAuthStatus'
$keySign    = Get-DsregField 'KeySignTest'

$joinType = 'Workgroup or unknown'
if ($aadJoined -eq 'YES' -and $domJoined -eq 'YES') { $joinType = 'Hybrid joined' }
elseif ($aadJoined -eq 'YES') { $joinType = 'Cloud joined' }
elseif ($domJoined -eq 'YES') { $joinType = 'On-premises domain joined' }

$trustModel = 'Not determined'
if ($cloudTgt -eq 'YES') { $trustModel = 'Cloud Kerberos trust' }
elseif ($ngcSet -eq 'YES') { $trustModel = 'Key or certificate trust' }

# ---------------------------------------------------------------- TPM
$tpm = $null
try { $tpm = Get-Tpm -ErrorAction Stop } catch { $degraded.Add('TPM state unreadable (needs administrator)') }

# ---------------------------------------------------------------- NGC container
# The NGC folder holds the protected key WHfB signs in with. NgcSet=YES with zero containers is
# the classic "Hello says it is set up but there is nothing to sign with" state.
$ngcPath = Join-Path $env:SystemRoot 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
$ngcCount = -1
try { $ngcCount = @(Get-ChildItem -LiteralPath $ngcPath -ErrorAction Stop).Count }
catch { $degraded.Add('NGC container folder unreadable (needs administrator)') }

# ---------------------------------------------------------------- policy
$pfwPath = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
function Get-PolicyValue([string]$Path, [string]$Name) {
    try { return "$((Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name)" }
    catch { return '' }
}
$polEnabled   = Get-PolicyValue $pfwPath 'Enabled'
$polReqSecDev = Get-PolicyValue $pfwPath 'RequireSecurityDevice'
$polCloudTrust= Get-PolicyValue $pfwPath 'UseCloudTrustForOnPremAuth'
$convenience  = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowDomainPINLogon'
$minPin       = Get-PolicyValue (Join-Path $pfwPath 'PINComplexity') 'MinimumPINLength'

# ---------------------------------------------------------------- device certificate
$devCert = 'Not found'
$devCertState = 'warn'
$devCertThumb = ''
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
        Where-Object { $_.Issuer -match 'MS-Organization-Access' } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($cert) {
        $devCertThumb = $cert.Thumbprint
        if ($cert.NotAfter -lt (Get-Date)) {
            $devCert = 'Expired ' + $cert.NotAfter.ToString('yyyy-MM-dd')
            $devCertState = 'bad'
        } else {
            $devCert = 'Present, valid until ' + $cert.NotAfter.ToString('yyyy-MM-dd')
            $devCertState = 'ok'
        }
    }
} catch { $degraded.Add('Device certificate store unreadable') }

# ---------------------------------------------------------------- sign-in history
# Anchors are interactive logons (4624 type 2), unlocks (4624 type 11) and workstation unlock
# (4801). The method is inferred by looking for a Hello or biometric event within a few seconds.
# Filtering happens SERVER-SIDE in XPath: a client-side filter over a busy Security log can take
# minutes, and Get-WinEvent will happily read 200,000 records before discarding them.
$since = (Get-Date).AddDays(-$Days)
$ms = [long]$Days * 86400000
$anchors = @()
$historyNote = ''
$xp = "*[(System[EventID=4801 and TimeCreated[timediff(@SystemTime)<=$ms]]) or (System[EventID=4624 and TimeCreated[timediff(@SystemTime)<=$ms]] and (EventData[Data[@Name='LogonType']='2'] or EventData[Data[@Name='LogonType']='11']))]"
try {
    $anchors = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 8000 -ErrorAction Stop | ForEach-Object {
        $sid = ''
        if ($_.Id -eq 4801) { $sid = "$($_.Properties[0].Value)" } else { $sid = "$($_.Properties[4].Value)" }
        if ($sid -match '^S-1-(5-21|12-1)') { [pscustomobject]@{ Time = $_.TimeCreated; Sid = $sid } }
    })
} catch {
    if ("$($_.Exception.Message)" -notmatch 'No events') {
        $historyNote = 'Security log unreadable - run as administrator'
        $degraded.Add('Sign-in history unavailable (Security log needs administrator)')
    }
}

$bioEvents  = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Biometrics/Operational';Id=1004;StartTime=$since} -ErrorAction SilentlyContinue |
    ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; IsFinger = ($_.Message -match 'fingerprint|MOC') } })
$faceEvents = @((Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Biometrics/Operational';Id=1702;StartTime=$since} -ErrorAction SilentlyContinue).TimeCreated)
$helloEvents= @((Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-HelloForBusiness/Operational';Id=5205,5702;StartTime=$since} -ErrorAction SilentlyContinue).TimeCreated)

function Test-Near([datetime]$When, $Times, [int]$Seconds) {
    foreach ($t in $Times) { if ([math]::Abs(($When - $t).TotalSeconds) -le $Seconds) { return $true } }
    return $false
}

$bySid = @{}
foreach ($a in $anchors) {
    $method = 'Password'
    $bio = $bioEvents | Where-Object { [math]::Abs(($a.Time - $_.Time).TotalSeconds) -le 8 } | Select-Object -First 1
    if ($bio) {
        if ($bio.IsFinger) { $method = 'Fingerprint' } else { $method = 'Face' }
    } elseif (Test-Near $a.Time $faceEvents 5) { $method = 'Face' }
    elseif (Test-Near $a.Time $helloEvents 8) { $method = 'PIN' }

    if (-not $bySid.ContainsKey($a.Sid)) {
        $bySid[$a.Sid] = @{ Face = 0; Fingerprint = 0; PIN = 0; Password = 0; Last = $null; LastMethod = '' }
    }
    $bySid[$a.Sid][$method]++
    if (-not $bySid[$a.Sid].Last -or $a.Time -gt $bySid[$a.Sid].Last) {
        $bySid[$a.Sid].Last = $a.Time
        $bySid[$a.Sid].LastMethod = $method
    }
}

# ---------------------------------------------------------------- users
function Resolve-Upn([string]$Sid) {
    foreach ($p in @("HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$Sid\IdentityCache\$Sid", "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$Sid")) {
        try {
            $item = Get-ItemProperty -LiteralPath $p -ErrorAction Stop
            foreach ($prop in $item.PSObject.Properties) {
                if ("$($prop.Value)" -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $prop.Value }
            }
        } catch { }
    }
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
    return $Sid
}

$winbio = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo'
$sids = @()
try { $sids += @(Get-ChildItem -LiteralPath $winbio -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)' } | ForEach-Object { $_.PSChildName }) } catch { }
try { $sids += @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -match '^S-1-(5-21|12-1)' -and -not $_.Special } | ForEach-Object { $_.SID }) } catch { }
$sids = @($sids | Select-Object -Unique)

$enrolRows = @()
foreach ($sid in $sids) {
    $factors = 0
    try { $factors = [int](Get-ItemProperty -LiteralPath "$winbio\$sid" -Name EnrolledFactors -ErrorAction Stop).EnrolledFactors } catch { }
    $fp   = 'No'; if ($factors -band 0x08) { $fp = 'Yes' }
    $face = 'No'; if ($factors -band 0x02) { $face = 'Yes' }
    $iris = 'No'; if ($factors -band 0x10) { $iris = 'Yes' }
    $pin  = '?';  if ($ngcSet -eq 'YES') { $pin = 'Yes' } elseif ($ngcSet -eq 'NO') { $pin = 'No' }
    $enrolled = ''
    $lastBio = ''
    try {
        $t = [int64](Get-ItemProperty -LiteralPath "$winbio\$sid" -Name BioEnrolledTime -ErrorAction Stop).BioEnrolledTime
        if ($t -gt 0) { $enrolled = [DateTime]::FromFileTimeUtc($t).ToString('yyyy-MM-dd') }
    } catch { }
    try {
        $t = [int64](Get-ItemProperty -LiteralPath "$winbio\$sid" -Name LastBioUseTime -ErrorAction Stop).LastBioUseTime
        if ($t -gt 0) { $lastBio = [DateTime]::FromFileTimeUtc($t).ToString('yyyy-MM-dd') }
    } catch { }
    $enrolRows += , @((Hide-Upn (Resolve-Upn $sid)), $pin, $fp, $face, $iris, $enrolled, $lastBio)
}

$usageRows = @()
$passwordHeavy = $false
$helloUsedAtAll = $false
foreach ($sid in $bySid.Keys) {
    $c = $bySid[$sid]
    $total = $c.Face + $c.Fingerprint + $c.PIN + $c.Password
    $helloCount = $c.Face + $c.Fingerprint + $c.PIN
    if ($helloCount -gt 0) { $helloUsedAtAll = $true }
    if ($total -ge 5 -and $c.Password -gt ($total / 2)) { $passwordHeavy = $true }
    $last = ''
    if ($c.Last) { $last = $c.Last.ToString('yyyy-MM-dd HH:mm') + ' (' + $c.LastMethod + ')' }
    $usageRows += , @((Hide-Upn (Resolve-Upn $sid)), "$($c.Face)", "$($c.Fingerprint)", "$($c.PIN)", "$($c.Password)", $last)
}

# ---------------------------------------------------------------- services
$serviceRows = @()
$coreServiceStopped = $false
foreach ($name in 'NgcSvc', 'NgcCtnrSvc', 'KeyIso', 'WbioSrvc', 'TokenBroker') {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    $status = 'not found'
    if ($svc) { $status = "$($svc.Status)" }
    # WbioSrvc and NgcCtnrSvc are trigger-started by design: Stopped is normal for them, and
    # flagging it produces a false alarm on a perfectly healthy device.
    $onDemand = ($name -eq 'WbioSrvc' -or $name -eq 'NgcCtnrSvc')
    $state = ''
    if ($status -eq 'Running') { $state = 'ok' }
    elseif ($onDemand -or $status -eq 'not found') { $state = '' }
    else { $state = 'bad'; $coreServiceStopped = $true }
    $label = $status
    if ($onDemand -and $status -ne 'Running') { $label = $status + ' (starts on demand)' }
    $serviceRows += (New-Row $name $label $state)
}

# ---------------------------------------------------------------- event-log error counts
function Get-ErrorCount([string]$LogName) {
    try { return @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Level=2;StartTime=$since} -ErrorAction Stop).Count }
    catch { return 0 }
}
$helloErrors = Get-ErrorCount 'Microsoft-Windows-HelloForBusiness/Operational'
$bioErrors   = Get-ErrorCount 'Microsoft-Windows-Biometrics/Operational'
$regErrors   = Get-ErrorCount 'Microsoft-Windows-User Device Registration/Admin'

# ---------------------------------------------------------------- audit policy
$logonAudit = 'Unknown'
$unlockAudit = 'Unknown'
try {
    $audit = (auditpol /get /subcategory:"Logon","Other Logon/Logoff Events" 2>$null) -join "`n"
    if ($audit -match '(?m)^\s*Logon\s+(Success|Success and Failure)') { $logonAudit = 'On' } else { $logonAudit = 'Off' }
    if ($audit -match 'Other Logon/Logoff Events\s+(Success|Success and Failure)') { $unlockAudit = 'On' } else { $unlockAudit = 'Off' }
} catch { $degraded.Add('Audit policy unreadable (needs administrator)') }

# ================================================================ build the report
Add-KvSection 'Device identity and trust' @(
    (New-Row 'Join type' $joinType '')
    (New-Row 'Trust model' $trustModel '')
    (New-Row 'AzureAdJoined' $aadJoined $(if ($aadJoined -eq 'YES') { 'ok' } else { 'bad' }))
    (New-Row 'DomainJoined' $domJoined '')
    (New-Row 'DeviceAuthStatus' $devAuth $(if ($devAuth -eq 'SUCCESS') { 'ok' } elseif ($devAuth) { 'bad' } else { '' }))
    (New-Row 'DeviceId' (Hide-Value (Get-DsregField 'DeviceId')) '')
    (New-Row 'Device certificate' $devCert $devCertState)
    (New-Row 'Device cert thumbprint' (Hide-Value $devCertThumb) '')
)

Add-KvSection 'Windows Hello provisioning' @(
    (New-Row 'NgcSet (Hello set up for this user)' $ngcSet $(if ($ngcSet -eq 'YES') { 'ok' } else { 'bad' }))
    (New-Row 'NGC containers present' $(if ($ngcCount -lt 0) { 'unreadable' } else { $ngcCount }) $(if ($ngcCount -gt 0) { 'ok' } elseif ($ngcCount -eq 0) { 'bad' } else { 'warn' }))
    (New-Row 'NgcKeyId' (Hide-Value (Get-DsregField 'NgcKeyId')) '')
    (New-Row 'KeyProvider' $keyProv '')
    (New-Row 'TpmProtected' $tpmProt $(if ($tpmProt -eq 'YES') { 'ok' } elseif ($tpmProt) { 'warn' } else { '' }))
    (New-Row 'KeySignTest' $keySign '')
)

Add-KvSection 'Single sign-on tokens' @(
    (New-Row 'AzureAdPrt' $prt $(if ($prt -eq 'YES') { 'ok' } else { 'bad' }))
    (New-Row 'AzureAdPrtUpdateTime' $prtUpdate '')
    (New-Row 'AzureAdPrtExpiryTime' $prtExpiry '')
    (New-Row 'OnPremTgt' $onPremTgt '')
    (New-Row 'CloudTgt' $cloudTgt $(if ($cloudTgt -eq 'YES') { 'ok' } else { '' }))
)

if ($tpm) {
    Add-KvSection 'Security chip (TPM)' @(
        (New-Row 'Present' $tpm.TpmPresent $(if ($tpm.TpmPresent) { 'ok' } else { 'bad' }))
        (New-Row 'Ready' $tpm.TpmReady $(if ($tpm.TpmReady) { 'ok' } else { 'bad' }))
        (New-Row 'Enabled' $tpm.TpmEnabled '')
        (New-Row 'Owned' $tpm.TpmOwned '')
    )
} else {
    Add-KvSection 'Security chip (TPM)' @( (New-Row 'TPM status' 'Unreadable - run as administrator' 'warn') )
}

Add-KvSection 'Policy' @(
    (New-Row 'Policy: Enabled' $(if ($polEnabled -eq '') { 'Not configured' } else { $polEnabled }) $(if ($polEnabled -eq '0') { 'bad' } elseif ($polEnabled -eq '1') { 'ok' } else { 'warn' }))
    (New-Row 'Policy: RequireSecurityDevice' $polReqSecDev '')
    (New-Row 'Policy: UseCloudTrustForOnPremAuth' $polCloudTrust '')
    (New-Row 'Convenience PIN (AllowDomainPINLogon)' $(if ($convenience -eq '1') { 'On' } elseif ($convenience -eq '') { 'Not configured' } else { 'Off' }) $(if ($convenience -eq '1') { 'warn' } else { 'ok' }))
    (New-Row 'Minimum PIN length' $minPin '')
)

Add-TableSection 'Per-user Windows Hello enrolment' @('User', 'PIN', 'Fingerprint', 'Face', 'Iris', 'Enrolled', 'Last biometric use') $enrolRows

$usageTitle = "Who signed in as what (last $Days days)"
if ($historyNote) { $usageTitle = $usageTitle + ' - ' + $historyNote }
Add-TableSection $usageTitle @('User', 'Face', 'Fingerprint', 'PIN', 'Password', 'Last sign-in') $usageRows

Add-KvSection 'Services' $serviceRows

Add-KvSection "Errors logged in the last $Days days" @(
    (New-Row 'HelloForBusiness' ("$helloErrors errors") $(if ($helloErrors -eq 0) { 'ok' } elseif ($helloErrors -lt 5) { 'warn' } else { 'bad' }))
    (New-Row 'Biometrics' ("$bioErrors errors") $(if ($bioErrors -eq 0) { 'ok' } elseif ($bioErrors -lt 5) { 'warn' } else { 'bad' }))
    (New-Row 'Device registration' ("$regErrors errors") $(if ($regErrors -eq 0) { 'ok' } elseif ($regErrors -lt 5) { 'warn' } else { 'bad' }))
)

Add-KvSection 'Audit readiness' @(
    (New-Row '"Logon" auditing' $logonAudit $(if ($logonAudit -eq 'On') { 'ok' } else { 'warn' }))
    (New-Row '"Other Logon/Logoff Events"' $unlockAudit $(if ($unlockAudit -eq 'On') { 'ok' } else { 'warn' }))
)

# ================================================================ verdict
# Ordered worst first. Every flag below maps to exactly one check in Detect-WHFBDeviceHealth.ps1,
# so the per-device report and the fleet detection never disagree.
$flags = New-Object System.Collections.Generic.List[string]
if ($aadJoined -ne 'YES')                 { $flags.Add('Device is not joined to the cloud directory (AzureAdJoined is not YES)') }
if ($devCertState -eq 'bad')              { $flags.Add('Device registration certificate has expired') }
if ($tpm -and -not $tpm.TpmReady)         { $flags.Add('Security chip (TPM) is not ready') }
if ($ngcSet -eq 'NO')                     { $flags.Add('Windows Hello is not set up for the signed-in user (NgcSet is NO)') }
if ($ngcSet -eq 'YES' -and $ngcCount -eq 0) { $flags.Add('NgcSet says YES but there is no NGC container on disk') }
if ($prt -ne 'YES')                       { $flags.Add('No single sign-on token (AzureAdPrt is not YES)') }
if ($coreServiceStopped)                  { $flags.Add('A service Windows Hello depends on is stopped') }
if ($polEnabled -eq '0')                  { $flags.Add('Policy explicitly disables Windows Hello (PassportForWork Enabled is 0)') }
if ($helloErrors -ge 5)                   { $flags.Add("Windows Hello logged $helloErrors errors in the last $Days days") }

# Not a fault, but the single most useful thing on the report: Hello is set up and the person
# still types a password most mornings. Reported separately so it never turns the verdict red.
$advice = New-Object System.Collections.Generic.List[string]
if ($ngcSet -eq 'YES' -and $passwordHeavy) { $advice.Add('Windows Hello is set up but a password was still the most used sign-in method') }
if ($ngcSet -eq 'YES' -and -not $helloUsedAtAll -and $anchors.Count -gt 0) { $advice.Add('Windows Hello is set up but no Hello sign-in was recorded in the window') }
if ($convenience -eq '1') { $advice.Add('Convenience PIN is enabled - that is a plain PIN, not Windows Hello for Business') }
if ($logonAudit -ne 'On' -or $unlockAudit -ne 'On') { $advice.Add('Sign-in auditing is incomplete, so the usage figures above under-report') }

$healthy = ($flags.Count -eq 0)
$verdictText = 'HEALTHY - Windows Hello for Business looks correctly set up'
if (-not $healthy) { $verdictText = 'NEEDS ATTENTION - ' + $flags.Count + ' blocking issue(s) found' }

$report = [ordered]@{
    computer  = $(if ($Anonymise) { '<masked>' } else { $env:COMPUTERNAME })
    generated = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    verdict   = [ordered]@{ healthy = $healthy; text = $verdictText; flags = @($flags) }
    advice    = @($advice)
    degraded  = @($degraded)
    sections  = @($sections)
}

try {
    $json = $report | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($JsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
} catch {
    Write-Error ("Could not write the report: {0}" -f $_.Exception.Message)
    exit 2
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host ("WHfB device report - {0}" -f $report.computer) -ForegroundColor White
    Write-Host ('-' * 58) -ForegroundColor DarkGray
    if ($healthy) { Write-Host $verdictText -ForegroundColor Green } else { Write-Host $verdictText -ForegroundColor Red }
    foreach ($f in $flags) { Write-Host ("  [blocker] " + $f) -ForegroundColor Red }
    foreach ($a in $advice) { Write-Host ("  [note]    " + $a) -ForegroundColor Yellow }
    foreach ($d in $degraded) { Write-Host ("  [gap]     " + $d) -ForegroundColor DarkYellow }
    Write-Host ''
    Write-Host ("  Join        : {0} / {1}" -f $joinType, $trustModel)
    Write-Host ("  NgcSet      : {0}      NGC containers: {1}" -f $ngcSet, $(if ($ngcCount -lt 0) { '?' } else { $ngcCount }))
    Write-Host ("  AzureAdPrt  : {0}      TPM ready     : {1}" -f $prt, $(if ($tpm) { $tpm.TpmReady } else { '?' }))
    Write-Host ("  Sign-ins    : {0} anchor events for {1} user(s)" -f $anchors.Count, $bySid.Count)
    Write-Host ''
    Write-Host ("Report written: {0}" -f $JsonPath) -ForegroundColor Green
    Write-Host 'Open whfb-device-report.html and load that file to read it.'
}

if ($flags.Count -gt 0) { exit 1 }
exit 0
