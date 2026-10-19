<#
.SYNOPSIS
    Intune Remediations: repairs the PRT / WAM / SSO faults that are safe to repair without a
    human, for the user who is actually affected, and refuses the rest on purpose.

.DESCRIPTION
    Runs straight after Detect-PrtSsoHealth.ps1 and works from the report it has just written
    (ProgramData\EndpointWeekly\PrtSso\PrtSso-latest.json). Each finding in that report carries the
    repair actions that apply to it; this script runs only those, in a fixed order, and only for
    users who are still signed in.

    WILL do (each one safe, reversible and a no-op on a healthy device):
      * Enable the AAD Analytic channel if it is off, so the next detection has transactions
      * Device join failure on a hybrid device -> trigger the Automatic-Device-Join task
      * TokenBroker disabled -> set it back to Manual and start it
      * NgcSvc / KeyIso stopped -> start them
      * Conditional Access compliance denial (AADSTS53000/53001/50097) -> trigger an MDM sync
      * WAM account inconsistency -> re-register Microsoft.AAD.BrokerPlugin for the user
      * Stale token state / missing PRT -> dsregcmd /refreshprt in the user's own context
      * Credential, UPN and stale-token problems a refresh cannot fix -> one toast to the user per
        24 hours asking them to lock and unlock (or sign out and in) with their current password

    WILL NOT do, by design:
      * Leave and re-join the device (dsregcmd /leave). It orphans the BitLocker key escrow and the
        Intune enrolment tied to the device ID. Opt in with $AllowHybridRejoin on hybrid devices only.
      * Clear the WAM/broker token cache. It signs the user out of every Microsoft 365 app. Opt in
        with $AllowWamCacheReset.
      * Change proxy or TLS inspection settings, federation (AD FS) settings, UPNs, Entra Connect
        sync or Conditional Access policy. Those are owned by other teams; the fix is logged.
      * Delete a Windows Hello container or clear a TPM.

    Every action and refusal is written to the Intune output and to remediation.log.

    Exit codes:
      0 = repairs completed and nothing that needs a human is outstanding
      1 = a repair failed, or a finding needs manual action (the device stays visible in Intune)

.NOTES
    Author  : Imran Awan
    Repo    : https://github.com/Imran76Awan/Daily-Tasks
    Context : Intune Remediations - run as SYSTEM, 64-bit. Pairs with Detect-PrtSsoHealth.ps1.
              Intune passes no parameters, so behaviour is set in the configuration block below.
#>

# ====================================================================== configuration (edit here)
$AllowAnalyticLogEnable   = $true    # turn on Microsoft-Windows-AAD/Analytic when it is off
$AllowHybridJoinTask      = $true    # start Automatic-Device-Join on hybrid devices
$AllowHybridRejoin        = $false   # DESTRUCTIVE: dsregcmd /leave + re-join when DeviceAuthStatus fails
$AllowServiceRepair       = $true    # TokenBroker / NgcSvc / KeyIso
$AllowMdmSync             = $true    # MDM sync for compliance-based Conditional Access denials
$AllowBrokerReRegister    = $true    # re-register Microsoft.AAD.BrokerPlugin for the user
$AllowWamCacheReset       = $false   # DISRUPTIVE: renames the user's broker token cache (one sign-in)
$AllowPrtRefresh          = $true    # dsregcmd /refreshprt in the user context
$NotifyUser               = $true    # toast the user when only they can fix it
$NotifyEveryHours         = 24
$MaxReportAgeMinutes      = 120
$ReportPath               = Join-Path $env:ProgramData 'EndpointWeekly\PrtSso'
# ===============================================================================================

$ErrorActionPreference = 'Continue'
$script:actions  = New-Object System.Collections.Generic.List[string]
$script:refused  = New-Object System.Collections.Generic.List[string]
$script:failures = New-Object System.Collections.Generic.List[string]
$LogPath = Join-Path $ReportPath 'remediation.log'

function Write-Log([string]$Message) {
    $line = ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
    Write-Output $line
    try { Add-Content -LiteralPath $LogPath -Value $line -ErrorAction Stop } catch { }
}
function Add-Action([string]$Text)  { $script:actions.Add($Text);  Write-Log "FIXED   $Text" }
function Add-Failure([string]$Text) { $script:failures.Add($Text); Write-Log "FAILED  $Text" }
function Add-Refusal([string]$Text) { $script:refused.Add($Text);  Write-Log "MANUAL  $Text" }

# ========================================================================= user-context execution
# Identical to the helper in Detect-PrtSsoHealth.ps1 - Intune Remediations upload single files, so
# it cannot be shared. Keep the two copies in step.
$script:UserPayload = @'
$ErrorActionPreference = 'Continue'
$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGS__')) | ConvertFrom-Json
$r = [ordered]@{ action = $a.action; ok = $true; error = ''; collectedUtc = (Get-Date).ToUniversalTime().ToString('o') }
try {
    switch ($a.action) {
        'refresh-prt' {
            $help = (& dsregcmd.exe /? 2>&1) -join "`n"
            if ($help -match '(?i)/refreshprt') {
                $r.actionOutput = (& dsregcmd.exe /refreshprt 2>&1) -join "`n"
                Start-Sleep -Seconds 10
            } else { $r.ok = $false; $r.error = 'dsregcmd /refreshprt is not available on this Windows build' }
        }
        'reregister-broker' {
            $m = Join-Path $env:windir 'SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Appxmanifest.xml'
            if (Test-Path -LiteralPath $m) { Add-AppxPackage -Register $m -DisableDevelopmentMode -ForceApplicationShutdown -ErrorAction Stop; $r.actionOutput = 'AAD.BrokerPlugin re-registered' }
            else { $r.ok = $false; $r.error = "manifest not found: $m" }
        }
        'wam-cache-reset' {
            $base = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy'
            $stamp = Get-Date -Format 'yyyyMMddHHmmss'
            $done = @()
            foreach ($sub in 'AC\TokenBroker', 'LocalState') {
                $p = Join-Path $base $sub
                if (Test-Path -LiteralPath $p) { Rename-Item -LiteralPath $p -NewName ((Split-Path $p -Leaf) + ".bak-$stamp") -ErrorAction Stop; $done += $sub }
            }
            $r.actionOutput = 'renamed: ' + ($done -join ', ')
        }
        'notify' {
            [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
            [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
            $esc = { param($s) [Security.SecurityElement]::Escape([string]$s) }
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml(("<toast><visual><binding template='ToastGeneric'><text>{0}</text><text>{1}</text></binding></visual></toast>" -f (& $esc $a.title), (& $esc $a.body)))
            $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
            $r.actionOutput = 'notification shown'
        }
    }
} catch { $r.ok = $false; $r.error = $_.Exception.Message }

$r.dsreg = (& dsregcmd.exe /status 2>&1) -join "`n"
$r.whoamiUpn = ((& whoami.exe /upn 2>&1) -join ' ').Trim()
$r.whoamiUpnExit = $LASTEXITCODE
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$r.name = $id.Name
$r.sid = $id.User.Value
try {
    $is = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    $r.wininet = [ordered]@{ proxyEnable = [int]$is.ProxyEnable; proxyServer = "$($is.ProxyServer)"; autoConfigUrl = "$($is.AutoConfigURL)"; proxyOverride = "$($is.ProxyOverride)" }
} catch { $r.wininet = $null }
try {
    $bp = Get-AppxPackage -Name 'Microsoft.AAD.BrokerPlugin' -ErrorAction Stop | Select-Object -First 1
    $r.brokerPlugin = if ($bp) { [ordered]@{ present = $true; version = "$($bp.Version)"; status = "$($bp.Status)" } } else { [ordered]@{ present = $false } }
} catch { $r.brokerPlugin = [ordered]@{ present = $null; error = $_.Exception.Message } }
$r.officeIdentities = @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    if ($p.EmailAddress) { [ordered]@{ email = "$($p.EmailAddress)"; provider = "$($p.ProviderId)" } } })
$tmp = $a.outFile + '.tmp'
$r | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
Move-Item -LiteralPath $tmp -Destination $a.outFile -Force
'@

function Test-IsSystem { return ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') }

function Initialize-SecureFolder([string]$Path) {
    # SYSTEM reads JSON from here, so standard users must not be able to pre-create or edit it.
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    if (Test-IsSystem) {
        & icacls.exe $Path /setowner '*S-1-5-32-544' /T /C /Q 2>&1 | Out-Null
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q 2>&1 | Out-Null
    }
}

function Get-InteractiveUsers {
    $seen = @{}
    $users = foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
        try {
            $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            $sid = (Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop).Sid
            if (-not $sid -or $seen.ContainsKey($sid)) { continue }
            $seen[$sid] = $true
            [pscustomobject]@{ account = ('{0}\{1}' -f $owner.Domain, $owner.User); sid = $sid; sessionId = $p.SessionId }
        } catch { }
    }
    return @($users)
}

function Invoke-AsUser($User, [hashtable]$PayloadArgs, [string]$WorkRoot, [int]$TimeoutSec = 120) {
    $runDir = Join-Path $WorkRoot ('run-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    $outFile = Join-Path $runDir 'out.json'
    $PayloadArgs.outFile = $outFile
    $argsB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($PayloadArgs | ConvertTo-Json -Compress)))
    $code = $script:UserPayload.Replace('__ARGS__', $argsB64)

    if (-not (Test-IsSystem) -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq $User.sid) {
        try { & ([scriptblock]::Create($code)) } catch { }
    } else {
        & icacls.exe $runDir /grant ('*{0}:(OI)(CI)M' -f $User.sid) /Q 2>&1 | Out-Null
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $psArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $enc"
        $action = if ([Environment]::OSVersion.Version.Build -ge 22000) {
            New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\conhost.exe') -Argument "--headless `"$ps`" $psArgs"
        } else { New-ScheduledTaskAction -Execute $ps -Argument $psArgs }
        $taskName = 'EndpointWeekly-PrtSso-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSec + 30))
        try {
            $principal = New-ScheduledTaskPrincipal -UserId $User.account -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        } catch {
            $principal = New-ScheduledTaskPrincipal -UserId $User.sid -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        }
        try {
            Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
            $deadline = (Get-Date).AddSeconds($TimeoutSec)
            while (-not (Test-Path -LiteralPath $outFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 750 }
        } finally {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    $data = $null
    try { if (Test-Path -LiteralPath $outFile) { $data = Get-Content -LiteralPath $outFile -Raw -ErrorAction Stop | ConvertFrom-Json } } catch { }
    Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    return $data
}

function Get-DsregField([string]$Text, [string]$Name) {
    if ($Text -match "(?m)^[ \t]*$Name[ \t]*:[ \t]*(.*)$") { return $Matches[1].TrimEnd() }
    return ''
}

function Get-PrtSnapshot($Payload) {
    $text = "$($Payload.dsreg)"
    [pscustomobject]@{ prt = (Get-DsregField $text 'AzureAdPrt'); update = (Get-DsregField $text 'AzureAdPrtUpdateTime') }
}

# ============================================================================== device-level fixes
function Start-NamedTask([string]$Path, [string]$Name, [string]$Label) {
    try {
        $task = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction Stop
        Start-ScheduledTask -InputObject $task -ErrorAction Stop
        Add-Action "triggered $Label"
    } catch { Add-Failure "could not trigger ${Label}: $($_.Exception.Message)" }
}

function Repair-Service([string]$Name) {
    try {
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if (-not $wmi) { Add-Failure "$Name service is missing"; return }
        if ($wmi.StartMode -eq 'Disabled') {
            Set-Service -Name $Name -StartupType Manual -ErrorAction Stop
            Add-Action "set $Name start type Disabled -> Manual"
        }
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Start-Service -Name $Name -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc.Refresh()
            if ($svc.Status -eq 'Running') { Add-Action "started $Name" } else { Add-Failure "$Name did not reach Running" }
        }
    } catch { Add-Failure "could not repair ${Name}: $($_.Exception.Message)" }
}

function Get-NotifyState {
    $p = Join-Path $ReportPath 'notify-state.json'
    $h = @{}
    try { (Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value } } catch { }
    return $h
}

function Save-NotifyState([hashtable]$State) {
    try { $State | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ReportPath 'notify-state.json') -Encoding UTF8 -ErrorAction Stop } catch { }
}

$script:NotifyText = @{
    UserCredential    = @('Sign-in needs your current password', 'Microsoft 365 could not sign you in silently. Press Windows+L to lock the PC, then unlock it with your CURRENT password.')
    IncorrectUpn      = @('Please sign out and back in', 'Your work account name has changed. Save your work, sign out of Windows and sign back in so Microsoft 365 stops asking for your password.')
    StaleToken        = @('Refresh your Microsoft 365 sign-in', 'Your sign-in token is out of date. Press Windows+L to lock the PC, then unlock it to refresh it.')
    ConditionalAccess = @('Your device is being checked', 'Access was blocked by your organisation''s security policy. Your device is syncing with Intune; if the prompts continue, contact the service desk.')
}

# =========================================================================================== main
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $native) { & $native -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath; exit $LASTEXITCODE }
}

Initialize-SecureFolder $ReportPath
Write-Log 'Remediation started'

# ---- load and sanity-check the detection report
$latest = Join-Path $ReportPath 'PrtSso-latest.json'
$report = $null
try { $report = Get-Content -LiteralPath $latest -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
if (-not $report -or $report.schema -ne 'endpointweekly.prt-sso/1') {
    Write-Log "No valid detection report at $latest - run Detect-PrtSsoHealth.ps1 first"
    exit 1
}
$age = ((Get-Date).ToUniversalTime() - ([datetime]$report.generatedUtc).ToUniversalTime()).TotalMinutes
if ($age -gt $MaxReportAgeMinutes -or $age -lt -5) {
    Write-Log ("Detection report is {0:N0} minutes old - refusing to act on stale data" -f $age)
    exit 1
}
if ($report.anonymised) {
    Write-Log 'Detection report is anonymised - user SIDs are masked, so only device-level repairs can run'
}
Write-Log ("Report: status={0} primary={1} categories={2}" -f $report.verdict.status, $report.verdict.primaryName, (@($report.verdict.categories) -join ','))

$catalog = $report.categoryCatalog
function Get-CategoryFix([string]$Category) { "$($catalog.$Category.name): $($catalog.$Category.fix)" }

$active = { param($f) $f.severity -eq 'Fail' -or $f.severity -eq 'Warn' }
$deviceFindings = @($report.deviceFindings | Where-Object { & $active $_ })
$deviceRepairs = @($deviceFindings | ForEach-Object { $_.repair } | Where-Object { $_ } | Select-Object -Unique)

# ---- 1. diagnostics: make sure the next detection can see 1006/1007 transactions
if ($AllowAnalyticLogEnable -and $report.analyticLog.enabled -ne $true -and -not $report.analyticLog.enabledByThisRun) {
    & wevtutil.exe sl 'Microsoft-Windows-AAD/Analytic' /e:true /q:true /ms:33554432 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Add-Action 'enabled the AAD Analytic channel (32 MB)' } else { Add-Failure "could not enable the AAD Analytic channel (wevtutil exit $LASTEXITCODE)" }
}

# ---- 2. device-level repairs
if ($deviceRepairs -contains 'hybrid-join-task') {
    if ($report.device.domainJoined -ne 'YES') {
        Add-Refusal 'device join failure on a non-hybrid device - re-joining an Entra joined device is an enrolment decision, not a repair'
    } else {
        if ($AllowHybridRejoin -and $report.device.deviceAuthStatus -and $report.device.deviceAuthStatus -ne 'SUCCESS' -and $report.device.azureAdJoined -eq 'YES') {
            # Opt-in only: the device object is gone or disabled, so a clean leave lets the task
            # register a new one. BitLocker escrow and Intune enrolment do not follow automatically.
            & dsregcmd.exe /leave 2>&1 | Out-Null
            Add-Action 'ran dsregcmd /leave (AllowHybridRejoin is on)'
        } elseif ($report.device.deviceAuthStatus -and $report.device.deviceAuthStatus -ne 'SUCCESS') {
            Add-Refusal "DeviceAuthStatus is '$($report.device.deviceAuthStatus)' - check the device object in Entra (enabled, not deleted). A leave/re-join is not automated unless AllowHybridRejoin is set."
        }
        if ($AllowHybridJoinTask) { Start-NamedTask '\Microsoft\Windows\Workplace Join\' 'Automatic-Device-Join' 'the Automatic-Device-Join task' }
    }
} elseif (@($deviceFindings | Where-Object { $_.category -eq 'DeviceJoin' -and $_.severity -eq 'Fail' }).Count) {
    Add-Refusal (Get-CategoryFix 'DeviceJoin')
}

if ($AllowServiceRepair) {
    if ($deviceRepairs -contains 'start-tokenbroker') { Repair-Service 'TokenBroker' }
    if ($deviceRepairs -contains 'start-ngc') { Repair-Service 'NgcSvc'; Repair-Service 'KeyIso' }
}

foreach ($cat in @($deviceFindings | Where-Object { $_.severity -eq 'Fail' -and @($_.repair | Where-Object { $_ }).Count -eq 0 -and $_.category -ne 'DeviceJoin' } | ForEach-Object { $_.category } | Select-Object -Unique)) {
    Add-Refusal (Get-CategoryFix $cat)
}

# ---- 3. per-user repairs, for users who are still signed in
$liveUsers = @{}
foreach ($u in (Get-InteractiveUsers)) { $liveUsers[$u.sid] = $u }
$notifyState = Get-NotifyState
$mdmSynced = $false

foreach ($ru in @($report.users)) {
    $sid = "$($ru.sid)"
    if ($sid -notmatch '^S-1-\d+(-\d+)+$') { continue }
    $findings = @($ru.findings | Where-Object { & $active $_ })
    if (-not $findings.Count) { continue }
    if (-not $liveUsers.ContainsKey($sid)) { Write-Log "SKIP    $($ru.account) is no longer signed in"; continue }
    $user = $liveUsers[$sid]
    $repairs = @($findings | ForEach-Object { $_.repair } | Where-Object { $_ } | Select-Object -Unique)
    $categories = @($findings | ForEach-Object { $_.category } | Select-Object -Unique)
    Write-Log ("USER    {0}: {1}" -f $user.account, ($categories -join ', '))

    if ($AllowServiceRepair -and $repairs -contains 'start-tokenbroker') { Repair-Service 'TokenBroker' }

    if ($repairs -contains 'mdm-sync' -and $AllowMdmSync -and -not $mdmSynced) {
        $push = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq 'PushLaunch' } | Select-Object -First 1
        if ($push) {
            try { Start-ScheduledTask -InputObject $push -ErrorAction Stop; Add-Action 'triggered an MDM sync (PushLaunch) so compliance is re-evaluated'; $mdmSynced = $true }
            catch { Add-Failure "could not trigger the MDM sync: $($_.Exception.Message)" }
        } else { Add-Failure 'PushLaunch task not found - is the device MDM enrolled?' }
    }

    if ($repairs -contains 'reregister-broker' -and $AllowBrokerReRegister) {
        $r = Invoke-AsUser $user @{ action = 'reregister-broker' } $ReportPath
        if ($r -and $r.ok) { Add-Action "re-registered AAD.BrokerPlugin for $($user.account)" }
        else { Add-Failure ("broker re-registration for {0}: {1}" -f $user.account, $(if ($r) { $r.error } else { 'no response from the user-context task' })) }
    }

    if ($categories -contains 'WamInconsistency') {
        if ($AllowWamCacheReset) {
            $r = Invoke-AsUser $user @{ action = 'wam-cache-reset' } $ReportPath
            if ($r -and $r.ok) { Add-Action "reset the broker token cache for $($user.account) ($($r.actionOutput))" }
            else { Add-Failure ("broker cache reset for {0}: {1}" -f $user.account, $(if ($r) { $r.error } else { 'no response' })) }
        } else { Write-Log 'NOTE    broker cache reset is available but off (AllowWamCacheReset = $false)' }
    }

    $refreshed = $null
    if ($repairs -contains 'refresh-prt' -and $AllowPrtRefresh) {
        $before = [pscustomobject]@{ prt = "$($ru.prt.AzureAdPrt)"; update = "$($ru.prt.AzureAdPrtUpdateTime)" }
        $r = Invoke-AsUser $user @{ action = 'refresh-prt' } $ReportPath -TimeoutSec 150
        if (-not $r) { Add-Failure "PRT refresh for $($user.account): no response from the user-context task" }
        elseif (-not $r.ok) { Add-Failure "PRT refresh for $($user.account): $($r.error)" }
        else {
            $after = Get-PrtSnapshot $r
            $refreshed = ($after.prt -eq 'YES' -and $after.update -and $after.update -ne $before.update)
            if ($refreshed) { Add-Action ("refreshed the PRT for {0} (AzureAdPrt {1} -> YES, updated {2})" -f $user.account, $before.prt, $after.update) }
            else { Add-Failure ("PRT refresh for {0} did not produce a new token (AzureAdPrt={1}, UpdateTime={2})" -f $user.account, $after.prt, $after.update) }
        }
    }

    # A fresh PRT proves the token path works end to end, so faults that only ever show up as a failed
    # token request (credential, stale, WAM, CA, Hello) are resolved. Configuration faults are not.
    $tokenPath = 'UserCredential', 'StaleToken', 'WamInconsistency', 'ConditionalAccess', 'WindowsHello', 'Unclassified'
    $outstanding = @($findings | Where-Object { $_.severity -eq 'Fail' -and @($_.repair | Where-Object { $_ }).Count -eq 0 } | ForEach-Object { $_.category } | Select-Object -Unique)
    if ($refreshed) { $outstanding = @($outstanding | Where-Object { $tokenPath -notcontains $_ }) }
    foreach ($cat in $outstanding) {
        Add-Refusal ("{0} -> {1}" -f $user.account, (Get-CategoryFix $cat))
    }

    # ---- tell the user, at most once per NotifyEveryHours per category
    if ($NotifyUser) {
        $notifyCat = $null
        foreach ($c in 'IncorrectUpn', 'UserCredential', 'ConditionalAccess', 'StaleToken') {
            if ($categories -notcontains $c) { continue }
            if ($refreshed -and $tokenPath -contains $c) { continue }
            $notifyCat = $c; break
        }
        $failed = @($findings | Where-Object { $_.severity -eq 'Fail' } | ForEach-Object { $_.category })
        $network = $failed -contains 'ProxyTls' -or $failed -contains 'Federation' -or @($deviceFindings | Where-Object { $_.category -eq 'ProxyTls' }).Count
        if ($notifyCat -and -not $network) {
            # A toast that asks for a lock/unlock is pointless while the network path is broken.
            $key = "$sid|$notifyCat"
            $last = $null
            if ($notifyState.ContainsKey($key)) { try { $last = [datetime]$notifyState[$key] } catch { } }
            if (-not $last -or ((Get-Date).ToUniversalTime() - $last.ToUniversalTime()).TotalHours -ge $NotifyEveryHours) {
                $text = $script:NotifyText[$notifyCat]
                $r = Invoke-AsUser $user @{ action = 'notify'; title = $text[0]; body = $text[1] } $ReportPath
                if ($r -and $r.ok) { Add-Action "notified $($user.account): $($text[0])"; $notifyState[$key] = (Get-Date).ToUniversalTime().ToString('o') }
                else { Write-Log ("NOTE    could not show a notification to {0}: {1}" -f $user.account, $(if ($r) { $r.error } else { 'no response' })) }
            }
        }
    }
}
Save-NotifyState $notifyState

# ---- result
$summary = ('Actions: {0}. Manual: {1}. Failures: {2}.' -f
    $(if ($script:actions.Count) { $script:actions -join '; ' } else { 'none' }), $script:refused.Count, $script:failures.Count)
Write-Log $summary
if ($script:failures.Count -gt 0 -or $script:refused.Count -gt 0) { exit 1 }
exit 0
