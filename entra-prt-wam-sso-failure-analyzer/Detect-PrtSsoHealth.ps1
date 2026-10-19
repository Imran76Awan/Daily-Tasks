<#
.SYNOPSIS
    PRT / WAM / SSO analyser and Intune Remediations detection script. Works out WHY a correctly
    joined device keeps prompting a user for Microsoft 365 sign-in, and for WHICH user.

.DESCRIPTION
    A Primary Refresh Token (PRT) is issued per user, per device. dsregcmd /status run as SYSTEM -
    which is how every Intune script runs by default - shows the SYSTEM account's SSO state, not
    the person who raised the ticket. This script therefore runs in two halves:

      * As SYSTEM it finds every interactive user (explorer.exe owners) and, for each one, starts a
        one-shot scheduled task IN THAT USER'S CONTEXT that captures dsregcmd /status, whoami /upn,
        the user SID, the WinINet proxy, the AAD.BrokerPlugin package and Office identities.
      * Back in SYSTEM it reads what a standard user cannot: the AAD Operational and Analytic
        channels, the device certificate, the primary-domain SID, the WinHTTP proxy and a TLS probe
        of the Entra sign-in endpoints.

    For each user it extracts AzureAdPrt, AzureAdPrtUpdateTime, AzureAdPrtExpiryTime, the
    AcquirePrtDiagnostics and RefreshPrtDiagnostics blocks (Attempt Status, Credential Type,
    Correlation ID, HTTP Error, HTTP Status, Server Error Code, Server Error Description),
    WamDefaultSet, WamDefaultAuthority, the current Windows UPN (CloudAP identity cache),
    whoami /upn, the user SID and the domain SID.

    AAD Analytic events are grouped into authentication transactions: event 1006 opens a PRT
    acquisition flow and event 1007 closes it. Operational events are attached to a transaction by
    time window and by Correlation ID, so the dsregcmd diagnostics, the Analytic flow and the
    Operational error all line up as one story.

    Every piece of evidence is classified into one of ten categories:
      Device join failure, User credential failure, Incorrect UPN, Federation failure,
      Proxy or TLS inspection interference, Conditional Access denial, Windows Hello credential
      issue, WAM account inconsistency, Stale token state, User SID missing from the token.

    WHAT IT CHANGES: by default exactly one thing - if the AAD Analytic channel is disabled it is
    enabled (32 MB), because without it there are no transactions to correlate. Pass -NoLogChanges
    to make the script strictly read-only. It also writes its JSON report and removes the one-shot
    scheduled task it created. Nothing is changed in Intune or Entra ID.

    Exit codes (Intune Remediations convention):
      0 = healthy, not applicable, or warnings only with nothing a repair could change
      1 = at least one failure, or a warning the remediation script can repair

.PARAMETER HoursBack
    How far back to read the AAD event logs. Default 24.

.PARAMETER StaleHours
    A PRT is renewed roughly every 4 hours while the user is active. An AzureAdPrtUpdateTime older
    than this is reported as a stale token. Default 12.

.PARAMETER ReportPath
    Folder for the JSON report. Default ProgramData\EndpointWeekly\PrtSso. The remediation script
    reads PrtSso-latest.json from here.

.PARAMETER NoLogChanges
    Do not enable the AAD Analytic channel. The script is then fully read-only.

.PARAMETER SkipNetworkTests
    Skip the TLS probe and the user realm lookup (no outbound connections).

.PARAMETER Anonymise
    Mask user names, UPNs, SIDs, device ID and correlation IDs in the JSON and console output.

.PARAMETER ShowReport
    Print the full console report even when running as SYSTEM.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Detect-PrtSsoHealth.ps1
    Intune Remediations detection (run as SYSTEM, 64-bit).

.EXAMPLE
    .\Detect-PrtSsoHealth.ps1 -HoursBack 72 -ShowReport
    Interactive triage from an elevated prompt with a longer event window.

.NOTES
    Author  : Imran Awan
    Repo    : https://github.com/Imran76Awan/Daily-Tasks
    Context : Intune Remediations - run as SYSTEM ("Run this script using the logged-on
              credentials" = No), 64-bit PowerShell = Yes. Pairs with Remediate-PrtSsoHealth.ps1.
    Tested  : Windows PowerShell 5.1 and PowerShell 7 syntax.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)] [int]$HoursBack = 24,
    [ValidateRange(4, 336)] [int]$StaleHours = 12,
    [string]$ReportPath = (Join-Path $env:ProgramData 'EndpointWeekly\PrtSso'),
    [switch]$NoLogChanges,
    [switch]$SkipNetworkTests,
    [switch]$Anonymise,
    [switch]$ShowReport,
    [int]$TransactionStartId = 1006,
    [int]$TransactionEndId = 1007
)

$ErrorActionPreference = 'Continue'
$script:Version = '1.0.0'
$script:BoundParams = $PSBoundParameters
$script:AnalyticLog = 'Microsoft-Windows-AAD/Analytic'
$script:OperationalLog = 'Microsoft-Windows-AAD/Operational'
$script:MicrosoftLoginHosts = 'login.microsoftonline.com', 'login.windows.net', 'login.microsoft.com', 'login.microsoftonline.us', 'login.partner.microsoftonline.cn'

# ==================================================================================== categories
# rank = root-cause order. A proxy that breaks TLS also produces credential and token errors, so the
# lower-ranked categories are only the primary verdict when nothing higher explains them.
$script:Categories = [ordered]@{
    DeviceJoin        = @{ rank = 1;  name = 'Device join failure';                  fix = 'The device identity itself is not usable. Check DeviceAuthStatus and the device object in Entra (enabled, not deleted). Hybrid: confirm the computer is in a synced OU and that Automatic-Device-Join completes.' }
    ProxyTls          = @{ rank = 2;  name = 'Proxy or TLS inspection interference'; fix = 'Exempt login.microsoftonline.com, device.login.microsoftonline.com and enterpriseregistration.windows.net from TLS inspection and proxy authentication. The device certificate is presented with TLS client authentication, which breaks behind an intercepting proxy.' }
    Federation        = @{ rank = 3;  name = 'Federation failure';                   fix = 'The federated IdP (AD FS or third party) did not return a usable token. Check the WS-Trust usernamemixed/windowstransport endpoints are enabled and reachable from the device and the IdP token-signing certificate is current in Entra.' }
    IncorrectUpn      = @{ rank = 4;  name = 'Incorrect UPN';                        fix = 'The UPN Windows signs in with does not resolve to this tenant. Use a routable, verified UPN suffix. After a UPN change the user must sign out and in again (lock/unlock is not enough) so CloudAP picks up the new name.' }
    UserSidMissing    = @{ rank = 5;  name = 'User SID missing from the token';      fix = 'Entra did not return the on-premises SID for the user. Confirm onPremisesSecurityIdentifier is synced by Entra Connect/Cloud Sync for this user, and that no proxy is rewriting the token response.' }
    UserCredential    = @{ rank = 6;  name = 'User credential failure';              fix = 'Entra rejected the credential (wrong, expired or changed password, locked or disabled account). The user should lock and unlock the PC with their CURRENT password; check the sign-in log for the Correlation ID.' }
    ConditionalAccess = @{ rank = 7;  name = 'Conditional Access denial';            fix = 'A Conditional Access policy blocked the token. Look up the Correlation ID in the Entra sign-in log to see which policy, then check device compliance in Intune.' }
    WindowsHello      = @{ rank = 8;  name = 'Windows Hello credential issue';       fix = 'PRT acquisition with the Hello key failed. Check NgcSvc/KeyIso and the TPM. A destructive Hello reset is NOT automated - see whfb-ngc-container-explained in this repo.' }
    WamInconsistency  = @{ rank = 9;  name = 'WAM account inconsistency';            fix = 'Web Account Manager has no or the wrong default account. Re-registering the AAD.BrokerPlugin package for the user usually fixes it; a broker cache reset (opt-in in the remediation) signs the user out of Microsoft 365 apps once.' }
    StaleToken        = @{ rank = 10; name = 'Stale token state';                    fix = 'The PRT is old or the refresh is failing. A PRT refresh (dsregcmd /refreshprt in the user context) or a lock/unlock normally fixes it.' }
    Unclassified      = @{ rank = 11; name = 'Unclassified PRT failure';             fix = 'The failure code is not in the classification table. Use the Correlation ID with the Entra sign-in log and the AAD Operational event text.' }
}

# =========================================================================== classification rules
# Matched against lower-cased evidence text: dsregcmd diagnostics, AAD event text and probe results.
# 0xcaa82xxx / 0x80072xxx wrap WinINet 12xxx errors; 0xcaa9xxxx is the WS-Trust family.
$script:Rules = @(
    @{ c = 'ProxyTls';          s = 'Fail'; r = '0x(?:caa8|8007)2(?:f8f|f7d|f05|f06|f0d)\b';      w = 'TLS certificate/secure-channel failure on an Entra endpoint (TLS inspection or a broken root store)' }
    @{ c = 'ProxyTls';          s = 'Fail'; r = '0x(?:caa8|8007)2(?:ee2|ee7|efd|efe)\b';          w = 'Network failure reaching Entra: timeout, name not resolved, cannot connect or connection aborted' }
    @{ c = 'ProxyTls';          s = 'Fail'; r = '0xc000023c|0xc00000be|0xc00000c4';                w = 'Network unreachable / unexpected network error during PRT acquisition' }
    @{ c = 'ProxyTls';          s = 'Fail'; r = 'http status\s*:?\s*407|proxy authentication required'; w = 'Proxy demanded authentication (HTTP 407) - the system context cannot answer it' }
    @{ c = 'Federation';        s = 'Fail'; r = '0xcaa9[0-9a-f]{4}\b';                             w = 'WS-Trust request to the federated IdP failed' }
    @{ c = 'Federation';        s = 'Fail'; r = 'aadsts(?:50008|50107|75005|750054|50000)\b';     w = 'Entra rejected the federated (SAML/WS-Fed) assertion' }
    @{ c = 'Federation';        s = 'Fail'; r = 'wstrust|ws-trust|mex endpoint|password_uri_is_empty|certificate_uri_is_empty'; w = 'Federation metadata/endpoint failure' }
    @{ c = 'IncorrectUpn';      s = 'Fail'; r = 'aadsts(?:50034|90002)\b';                         w = 'User or tenant not found for the UPN being used' }
    @{ c = 'IncorrectUpn';      s = 'Fail'; r = '0xc000005f|0xc004844c|username_is_malformed';     w = 'User realm discovery failed or the UPN is malformed' }
    @{ c = 'UserSidMissing';    s = 'Fail'; r = '0xc004848a|user_sid_is_empty|sid is (?:missing|empty)'; w = 'The ID token returned by Entra has no user SID' }
    @{ c = 'UserCredential';    s = 'Fail'; r = 'aadsts(?:50126|50053|50055|50056|50057|50144|50173|50132|50133)\b'; w = 'Entra rejected the credential (bad/expired/changed password, locked or disabled account)' }
    @{ c = 'UserCredential';    s = 'Fail'; r = '0xc000006a|0xc0000234|0xc0000071|0xc0000224|0xc0000072|0xc000006e'; w = 'Windows logon status: wrong password, locked, expired, must change or disabled' }
    @{ c = 'ConditionalAccess'; s = 'Fail'; r = 'aadsts(?:53000|53001|53002|53003|53004|50097|530002|530003|50158)\b'; w = 'Conditional Access blocked the token (compliance, join type, app or block policy)' }
    @{ c = 'ConditionalAccess'; s = 'Warn'; r = 'aadsts(?:50076|50079|50074)\b';                   w = 'MFA required for this token - the silent PRT/WAM request cannot satisfy it' }
    @{ c = 'DeviceJoin';        s = 'Fail'; r = 'aadsts(?:135011|700003|50155|135010)\b';          w = 'Device object disabled, deleted or failed device authentication' }
    @{ c = 'DeviceJoin';        s = 'Fail'; r = '0x801c[0-9a-f]{4}\b';                             w = 'Device registration (DSREG) error' }
    @{ c = 'WindowsHello';      s = 'Fail'; r = '0x8009(?:0016|0030|002d|0029)\b|0x8028[0-9a-f]{4}\b'; w = 'Key or TPM error while signing with the Hello/device key' }
    @{ c = 'WamInconsistency';  s = 'Warn'; r = '0xcaa5001c|token broker operation failed';        w = 'Token broker (WAM) operation failed' }
    @{ c = 'StaleToken';        s = 'Warn'; r = 'aadsts(?:70008|700082|70043|50089)\b|0x80070520'; w = 'Refresh token or session expired / logon session no longer exists' }
)

# =================================================================================== small helpers
function ConvertTo-NormalCode([string]$Code) {
    # dsregcmd and the event log show the same status as 0xC000006D, 0xc000006d or -1073741715.
    if (-not $Code) { return '' }
    $c = $Code.Trim()
    if ($c -match '^-\d+$') { return ('0x{0:x8}' -f [uint32]([int64]$c + 4294967296)) }
    if ($c -match '^0x([0-9a-fA-F]{1,8})$') { return ('0x{0}' -f $Matches[1].ToLower().PadLeft(8, '0')) }
    return $c.ToLower()
}

function Test-SuccessCode([string]$Code) {
    $n = ConvertTo-NormalCode $Code
    return (-not $n) -or $n -eq '0x00000000'
}

function ConvertFrom-DsregTime([string]$Text) {
    if ($Text -match '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
        return [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
    }
    return $null
}

function Get-EvidenceCodes([string]$Text) {
    $codes = New-Object System.Collections.Generic.List[string]
    if (-not $Text) { return @() }
    foreach ($m in [regex]::Matches($Text, '\b0x[0-9a-fA-F]{8}\b')) {
        $n = ConvertTo-NormalCode $m.Value
        if ($n -ne '0x00000000' -and -not $codes.Contains($n)) { $codes.Add($n) }
    }
    foreach ($m in [regex]::Matches($Text, 'AADSTS\d{5,7}')) {
        $n = $m.Value.ToUpper()
        if (-not $codes.Contains($n)) { $codes.Add($n) }
    }
    return @($codes)
}

function Get-CorrelationIds([string]$Text) {
    $ids = New-Object System.Collections.Generic.List[string]
    if (-not $Text) { return @() }
    foreach ($m in [regex]::Matches($Text, '(?i)correlation\s*id\s*[:=]?\s*\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')) {
        $v = $m.Groups[1].Value.ToLower()
        if (-not $ids.Contains($v)) { $ids.Add($v) }
    }
    return @($ids)
}

function Get-Upns([string]$Text) {
    if (-not $Text) { return @() }
    return @([regex]::Matches($Text, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+') |
        ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique)
}

function Hide-Text([string]$Text, [string]$Kind = 'value') {
    if (-not $Anonymise -or -not $Text) { return $Text }
    switch ($Kind) {
        'upn' {
            if ($Text -match '^([^@]+)@(.+)$') { return ('{0}***@<domain>' -f $Matches[1].Substring(0, [Math]::Min(2, $Matches[1].Length))) }
            return '<masked>'
        }
        'sid' {
            if ($Text -match '^(S-1-\d+-\d+)-') { return ($Matches[1] + '-<masked>') }
            return '<masked>'
        }
        'account' {
            if ($Text -match '^([^\\]+)\\(.+)$') { return ('{0}\{1}***' -f $Matches[1], $Matches[2].Substring(0, [Math]::Min(2, $Matches[2].Length))) }
            return '<masked>'
        }
        default { return '<masked>' }
    }
}

function Hide-Evidence([string]$Text) {
    # Masks UPNs and GUIDs inside free text (event messages, server error descriptions).
    if (-not $Anonymise -or -not $Text) { return $Text }
    $t = [regex]::Replace($Text, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+', '<upn>')
    $t = [regex]::Replace($t, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<guid>')
    return [regex]::Replace($t, 'S-1-5-21-[\d-]+|S-1-12-1-[\d-]+', '<sid>')
}

# ================================================================================ dsregcmd parser
# Field names are matched per line with [ \t] rather than \s, so an empty value never swallows the
# next line. The two diagnostic blocks reuse the same field names (Attempt Status, HTTP status, ...)
# so they are collected separately instead of first-wins.
$script:DiagFields = 'Previous Prt Attempt', 'Attempt Status', 'User Identity', 'Credential Type', 'Correlation ID',
    'Endpoint URI', 'HTTP Method', 'HTTP Error', 'HTTP status', 'Server Error Code', 'Server Error Description'

function ConvertFrom-DsregStatus([string]$Text) {
    $result = [ordered]@{ fields = [ordered]@{}; sections = [ordered]@{}; acquire = $null; refresh = $null }
    if (-not $Text) { return $result }
    $section = 'Header'
    $block = $null
    foreach ($raw in ($Text -split "`r?`n")) {
        if ($raw -match '^\s*\|\s*(.+?)\s*\|\s*$') { $section = $Matches[1]; $block = $null; continue }
        if ($raw -match '^\s*\+-+\+\s*$') { continue }
        if ($raw -notmatch '^[ \t]*([A-Za-z][A-Za-z0-9 _\-\.\(\)/]*?)[ \t]*:[ \t]*(.*)$') { continue }
        $key = $Matches[1].Trim()
        $value = $Matches[2].Trim()

        if ($key -eq 'AcquirePrtDiagnostics' -or $key -eq 'RefreshPrtDiagnostics') {
            $name = if ($key -eq 'AcquirePrtDiagnostics') { 'acquire' } else { 'refresh' }
            $result[$name] = [ordered]@{ state = $value }
            $block = $name
            continue
        }
        if ($block -and ($script:DiagFields -contains $key)) {
            $result[$block][$key] = $value
            continue
        }
        $block = $null
        if (-not $result.sections.Contains($section)) { $result.sections[$section] = [ordered]@{} }
        if (-not $result.sections[$section].Contains($key)) { $result.sections[$section][$key] = $value }
        if (-not $result.fields.Contains($key)) { $result.fields[$key] = $value }
    }
    return $result
}

function Get-DsregValue($Parsed, [string]$Name) {
    if ($Parsed -and $Parsed.fields.Contains($Name)) { return [string]$Parsed.fields[$Name] }
    return ''
}

# ===================================================================================== findings
function New-Finding([string]$Category, [string]$Severity, [string]$Title, [string]$Evidence, [string]$Source,
                     [string]$CorrelationId = '', [string[]]$Repair = @(), [string]$UserSid = '') {
    [pscustomobject][ordered]@{
        category      = $Category
        categoryName  = $script:Categories[$Category].name
        severity      = $Severity
        title         = $Title
        evidence      = $Evidence
        source        = $Source
        correlationId = $CorrelationId
        repair        = @($Repair | Where-Object { $_ })
        userSid       = $UserSid
        transaction   = $null
    }
}

function Get-RepairFor([string]$Category, [string]$EvidenceText, $Context) {
    switch ($Category) {
        'DeviceJoin'        { if ($Context.domainJoined -eq 'YES') { return @('hybrid-join-task') } else { return @() } }
        'ConditionalAccess' { if ($EvidenceText -match '(?i)aadsts(?:53000|53001|50097)\b') { return @('mdm-sync', 'refresh-prt') } else { return @() } }
        'WamInconsistency'  { return @('start-tokenbroker', 'reregister-broker', 'refresh-prt') }
        'StaleToken'        { return @('refresh-prt') }
        default             { return @() }
    }
}

function Invoke-Rules([string]$EvidenceText, [string]$Source, [string]$CorrelationId, [string]$UserSid, $Context) {
    # One finding per category per piece of evidence: the first (most specific) rule wins.
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $lower = "$EvidenceText".ToLower()
    foreach ($rule in $script:Rules) {
        if ($seen.ContainsKey($rule.c)) { continue }
        if ($lower -match $rule.r) {
            $seen[$rule.c] = $true
            $hit = $Matches[0]
            $out.Add((New-Finding -Category $rule.c -Severity $rule.s -Title $rule.w -Evidence ("matched '{0}' in: {1}" -f $hit, (Limit-Text $EvidenceText 400)) `
                -Source $Source -CorrelationId $CorrelationId -Repair (Get-RepairFor $rule.c $EvidenceText $Context) -UserSid $UserSid))
        }
    }
    return $out
}

function Limit-Text([string]$Text, [int]$Max) {
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -le $Max) { return $t }
    return $t.Substring(0, $Max) + '...'
}

function Get-DiagFindings($Diag, [string]$BlockName, $Prt, [string]$UserSid, $Context) {
    # Turns one AcquirePrtDiagnostics / RefreshPrtDiagnostics block into findings.
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Diag -or $Diag.state -ne 'PRESENT') { return $out }
    $status    = ConvertTo-NormalCode $Diag['Attempt Status']
    $httpError = ConvertTo-NormalCode $Diag['HTTP Error']
    $httpCode  = "$($Diag['HTTP status'])"
    $srvCode   = "$($Diag['Server Error Code'])"
    $srvDesc   = "$($Diag['Server Error Description'])"
    $credType  = "$($Diag['Credential Type'])"
    $corr      = "$($Diag['Correlation ID'])".ToLower()
    $endpoint  = "$($Diag['Endpoint URI'])"
    $source    = "dsregcmd $BlockName"

    $failed = (-not (Test-SuccessCode $status)) -or $srvCode -or (-not (Test-SuccessCode $httpError))
    if (-not $failed) { return $out }

    # A diagnostic block is history: if the PRT was renewed after the attempt, it is not the current fault.
    $attempt = ConvertFrom-DsregTime $Diag['Previous Prt Attempt']
    $historical = $Prt.present -and $Prt.updateTime -and $attempt -and ($Prt.updateTime -gt $attempt)

    $text = 'Attempt Status: {0}; HTTP Error: {1}; HTTP status: {2}; Server Error Code: {3}; Server Error Description: {4}; Credential Type: {5}; Endpoint: {6}' -f
        $status, $httpError, $httpCode, $srvCode, $srvDesc, $credType, $endpoint

    $found = New-Object System.Collections.Generic.List[object]
    if (-not (Test-SuccessCode $httpError)) {
        $found.Add((New-Finding 'ProxyTls' 'Fail' "The token request never got an HTTP answer from the identity endpoint (HTTP Error $httpError)" $text $source $corr @() $UserSid))
    }
    foreach ($f in (Invoke-Rules $text $source $corr $UserSid $Context)) { $found.Add($f) }

    $endpointHost = ''
    try { if ($endpoint) { $endpointHost = ([uri]$endpoint).Host.ToLower() } } catch { }
    if ($endpointHost -and ($script:MicrosoftLoginHosts -notcontains $endpointHost) -and -not ($found | Where-Object { $_.category -eq 'Federation' })) {
        $found.Add((New-Finding 'Federation' 'Fail' "PRT acquisition failed against the federated endpoint $endpointHost" $text $source $corr @() $UserSid))
    }
    if ($found.Count -eq 0 -and $status -eq '0xc000006d' -and $srvCode -eq 'invalid_grant') {
        $found.Add((New-Finding 'UserCredential' 'Fail' 'Logon failure with invalid_grant from Entra' $text $source $corr @() $UserSid))
    }
    if ($found.Count -eq 0 -and $status -eq '0xc00000d0') {
        $found.Add((New-Finding 'StaleToken' 'Warn' 'Entra returned a server error (5xx) - usually transient; a refresh retries it' $text $source $corr @('refresh-prt') $UserSid))
    }
    if ($found.Count -eq 0 -and $credType -match '(?i)ngc|hello|key') {
        $found.Add((New-Finding 'WindowsHello' 'Fail' "PRT acquisition with credential type '$credType' failed" $text $source $corr @() $UserSid))
    }
    if ($found.Count -eq 0) {
        $found.Add((New-Finding 'Unclassified' 'Fail' "PRT $BlockName failed with $status" $text $source $corr @() $UserSid))
    }
    foreach ($f in $found) {
        if ($historical) {
            $f.severity = 'Info'
            $f.title = '(historical - PRT renewed since) ' + $f.title
            $f.repair = @()
        }
        $out.Add($f)
    }
    return $out
}

# ================================================================================ event handling
function Get-AadEvents([string]$LogName, [datetime]$SinceUtc, [int]$Max, [switch]$Analytic) {
    $ms = [int64]((Get-Date).ToUniversalTime() - $SinceUtc).TotalMilliseconds
    $xp = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $raw = @(Get-WinEvent -LogName $LogName -FilterXPath $xp -MaxEvents $Max -Oldest:$Analytic -ErrorAction Stop)
    $list = foreach ($e in $raw) {
        # FormatMessage is the slow part, so Analytic events only pay for it when they matter.
        $text = ''
        $wantMessage = (-not $Analytic) -or $e.Level -le 3 -or $e.Id -eq $TransactionStartId -or $e.Id -eq $TransactionEndId
        if ($wantMessage) { try { $text = $e.Message } catch { } }
        if (-not $text) { $text = (@($e.Properties | ForEach-Object { "$($_.Value)" }) -join ' | ') }
        [pscustomobject]@{
            time    = $e.TimeCreated.ToUniversalTime()
            id      = $e.Id
            level   = [int]$e.Level
            log     = $(if ($Analytic) { 'Analytic' } else { 'Operational' })
            pid     = $e.ProcessId
            tid     = $e.ThreadId
            userSid = $(if ($e.UserId) { $e.UserId.Value } else { '' })
            text    = "$text"
        }
    }
    return @($list | Sort-Object time)
}

function Test-NoEvents($ErrorRecord) {
    # Get-WinEvent throws when a filter matches nothing; the error ID is stable across languages.
    return "$($ErrorRecord.FullyQualifiedErrorId)" -match 'NoMatchingEventsFound'
}

function Group-AadTransactions($AnalyticEvents, $OperationalEvents, [int]$StartId, [int]$EndId) {
    # 1006 opens a PRT acquisition flow, 1007 closes it, everything between belongs to it. A 1006
    # arriving while a flow is still open closes the previous one as unterminated.
    $txs = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($e in $AnalyticEvents) {
        if ($e.id -eq $StartId) {
            if ($current) { $current.complete = $false; $txs.Add($current) }
            $current = [pscustomobject]@{ start = $e.time; end = $e.time; complete = $false; events = (New-Object System.Collections.Generic.List[object]) }
            $current.events.Add($e)
            continue
        }
        if (-not $current) { continue }
        $current.events.Add($e)
        $current.end = $e.time
        if ($e.id -eq $EndId) { $current.complete = $true; $txs.Add($current); $current = $null }
    }
    if ($current) { $txs.Add($current) }

    $index = 0
    $result = foreach ($t in $txs) {
        $index++
        $evs = $t.events.ToArray()
        $allText = ($evs | ForEach-Object { $_.text }) -join "`n"
        $corr = @(Get-CorrelationIds $allText)
        $window = @($OperationalEvents | Where-Object { $_.time -ge $t.start.AddSeconds(-2) -and $_.time -le $t.end.AddSeconds(5) })
        $byCorr = @()
        if ($corr.Count) { $byCorr = @($OperationalEvents | Where-Object { $ev = $_; @(Get-CorrelationIds $ev.text | Where-Object { $corr -contains $_ }).Count -gt 0 }) }
        $ops = @(@($window) + @($byCorr) | Sort-Object time, id -Unique)
        $opText = ($ops | ForEach-Object { $_.text }) -join "`n"
        $corr = @(@($corr) + @(Get-CorrelationIds $opText) | Select-Object -Unique)
        $codes = @(Get-EvidenceCodes ($allText + "`n" + $opText))
        $errors = @(@($evs) + @($ops) | Where-Object { $_.level -ge 1 -and $_.level -le 2 })
        $sids = @(@($evs) + @($ops) | Where-Object { $_.userSid -and $_.userSid -ne 'S-1-5-18' } | ForEach-Object { $_.userSid } | Select-Object -Unique)
        $outcome = if ($errors.Count -or $codes.Count) { 'Failed' } elseif ($t.complete) { 'Succeeded' } else { 'Unterminated' }
        [pscustomobject][ordered]@{
            index             = $index
            start             = $t.start.ToString('o')
            end               = $t.end.ToString('o')
            durationMs        = [int]($t.end - $t.start).TotalMilliseconds
            complete          = $t.complete
            outcome           = $outcome
            analyticEvents    = $evs.Count
            operationalEvents = $ops.Count
            correlationIds    = @($corr)
            errorCodes        = @($codes)
            userSids          = @($sids)
            upns              = @(Get-Upns ($allText + ' ' + $opText))
            categories        = @()
            evidence          = (Limit-Text ((@($errors | ForEach-Object { $_.text }) + @($ops | Where-Object { $_.level -le 3 } | ForEach-Object { $_.text })) -join ' || ') 1500)
            timeline          = @((@($evs) + @($ops)) | Sort-Object time | Select-Object -First 80 | ForEach-Object {
                                    [pscustomobject]@{ time = $_.time.ToString('o'); log = $_.log; id = $_.id; level = $_.level; text = (Limit-Text $_.text 300) } })
        }
    }
    return @($result)
}

# ========================================================================= user-context execution
# The same helper lives in Remediate-PrtSsoHealth.ps1. It runs a fixed payload as the signed-in
# user through a one-shot scheduled task, because Intune runs this script as SYSTEM and PRT/WAM
# state only exists in the user's own logon session. The payload never runs with more rights than
# the user already has, and SYSTEM only ever parses its output as JSON.
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
    # SYSTEM later reads JSON from here, so standard users must not be able to pre-create or edit it.
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
        # Interactive technician run for the current user: no scheduled task needed.
        try { & ([scriptblock]::Create($code)) } catch { }
    } else {
        & icacls.exe $runDir /grant ('*{0}:(OI)(CI)M' -f $User.sid) /Q 2>&1 | Out-Null
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $psArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $enc"
        # conhost --headless avoids the console window flashing on the user's screen (Windows 11).
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

# ============================================================================== device-level data
function Get-DomainSids {
    # HKLM\SECURITY is readable by SYSTEM only. PolDmS is the primary (AD) domain SID, PolAcDmS the
    # local account domain SID. Both are cached locally, so this works with no domain controller.
    $r = [ordered]@{ domainSid = ''; localSid = ''; domain = ''; source = '' }
    try { $r.domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { }
    foreach ($pair in @(@('domainSid', 'PolDmS'), @('localSid', 'PolAcDmS'))) {
        try {
            $bytes = (Get-ItemProperty -LiteralPath "HKLM:\SECURITY\Policy\$($pair[1])" -ErrorAction Stop).'(default)'
            if ($bytes -and $bytes.Length -ge 8) { $r[$pair[0]] = (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value; $r.source = 'LSA policy' }
        } catch { }
    }
    if (-not $r.domainSid) {
        try {
            $sid = (New-Object Security.Principal.NTAccount("$env:COMPUTERNAME`$")).Translate([Security.Principal.SecurityIdentifier]).Value
            $r.domainSid = ($sid -replace '-\d+$', '')
            $r.source = 'machine account lookup'
        } catch { }
    }
    return $r
}

function Get-SidKind([string]$Sid, $DomainSids) {
    if (-not $Sid) { return 'Unknown' }
    if ($Sid -like 'S-1-12-1-*') { return 'EntraID' }
    $prefix = $Sid -replace '-\d+$', ''
    if ($DomainSids.localSid -and $prefix -eq $DomainSids.localSid) { return 'Local' }
    if ($DomainSids.domainSid -and $prefix -eq $DomainSids.domainSid) { return 'ActiveDirectory' }
    if ($Sid -like 'S-1-5-21-*') { return 'ActiveDirectory (other domain)' }
    return 'Other'
}

function Get-CachedWindowsUpn([string]$Sid) {
    # CloudAP's identity cache holds the UPN Windows actually uses to request this user's PRT.
    $path = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$Sid\IdentityCache\$Sid"
    try { return "$((Get-ItemProperty -LiteralPath $path -ErrorAction Stop).UserName)" } catch { return '' }
}

function Get-WinHttpProxy {
    $text = (& netsh.exe winhttp show proxy 2>&1) -join "`n"
    $r = [ordered]@{ direct = $true; server = ''; bypass = ''; raw = (Limit-Text $text 300) }
    if ($text -match '(?im)Proxy Server\(s\)\s*:\s*(\S.*)$') { $r.server = $Matches[1].Trim(); $r.direct = $false }
    if ($text -match '(?im)Bypass List\s*:\s*(\S.*)$') { $r.bypass = $Matches[1].Trim() }
    return $r
}

function Test-TlsEndpoint([string]$HostName, $WinHttp) {
    $r = [ordered]@{ host = $HostName; tcp = $false; tls = $false; viaProxy = $false; subject = ''; issuer = ''; root = ''; policyErrors = ''; intercepted = $false; error = '' }
    $state = @{ errors = '' }
    $callback = [Net.Security.RemoteCertificateValidationCallback] ({ param($s, $c, $ch, $e) $state.errors = "$e"; $true }.GetNewClosure())
    $cert = $null
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, 443, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(5000)) { throw 'TCP connect timed out' }
        $client.EndConnect($iar)
        $r.tcp = $true
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($HostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $r.tls = $true
        $ssl.Dispose()
    } catch {
        $r.error = $_.Exception.Message
    } finally { $client.Dispose() }

    if (-not $cert -and -not $WinHttp.direct -and $WinHttp.server) {
        # Direct path blocked: look at the certificate the WinHTTP proxy hands back instead.
        try {
            $proxy = ($WinHttp.server -split ';')[0] -replace '^(https?=)', ''
            $req = [Net.HttpWebRequest]::Create("https://$HostName/")
            $req.Proxy = New-Object Net.WebProxy("http://$proxy")
            $req.Timeout = 8000
            try { $resp = $req.GetResponse(); $resp.Close() } catch [Net.WebException] { if ($_.Exception.Response) { $_.Exception.Response.Close() } }
            if ($req.ServicePoint.Certificate) {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($req.ServicePoint.Certificate)
                $r.viaProxy = $true; $r.tls = $true
            }
        } catch { $r.error += " | via proxy: $($_.Exception.Message)" }
    }

    if ($cert) {
        $r.subject = $cert.Subject
        $r.issuer = $cert.Issuer
        $r.policyErrors = $state.errors
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        [void]$chain.Build($cert)
        if ($chain.ChainElements.Count) { $r.root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject }
        # Microsoft sign-in endpoints chain to DigiCert or Microsoft roots. Anything else is a proxy
        # re-signing the connection.
        $r.intercepted = -not (($r.issuer + ' ' + $r.root) -match '(?i)Microsoft|DigiCert|Baltimore CyberTrust')
    }
    return $r
}

function Get-UserRealm([string]$Upn) {
    if (-not $Upn -or $Upn -notmatch '@') { return $null }
    try {
        $u = 'https://login.microsoftonline.com/common/userrealm/{0}?api-version=2.1' -f [uri]::EscapeDataString($Upn)
        $r = Invoke-RestMethod -Uri $u -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        return [ordered]@{ nameSpaceType = "$($r.NameSpaceType)"; domain = "$($r.DomainName)"; federationProtocol = "$($r.federation_protocol)"; authUrl = "$($r.AuthURL)"; error = '' }
    } catch { return [ordered]@{ nameSpaceType = ''; error = $_.Exception.Message } }
}

# ================================================================================ per-user analysis
function Get-UserAnalysis($User, $Payload, $Device, $Transactions, $Operational, [bool]$SingleUser, $Realm) {
    $findings = New-Object System.Collections.Generic.List[object]
    $ctx = @{ domainJoined = $Device.domainJoined }
    $parsed = ConvertFrom-DsregStatus "$($Payload.dsreg)"
    $prtFlag = Get-DsregValue $parsed 'AzureAdPrt'
    $update = ConvertFrom-DsregTime (Get-DsregValue $parsed 'AzureAdPrtUpdateTime')
    $expiry = ConvertFrom-DsregTime (Get-DsregValue $parsed 'AzureAdPrtExpiryTime')
    $now = (Get-Date).ToUniversalTime()
    $prt = [pscustomobject]@{ present = ($prtFlag -eq 'YES'); updateTime = $update; expiryTime = $expiry }
    $sid = "$($Payload.sid)"
    if (-not $sid) { $sid = $User.sid }
    $sidKind = Get-SidKind $sid $Device.sids
    $whoamiUpn = ''
    if ($Payload.whoamiUpnExit -eq 0 -and "$($Payload.whoamiUpn)" -match '@') { $whoamiUpn = "$($Payload.whoamiUpn)".Trim() }
    $windowsUpn = Get-CachedWindowsUpn $sid
    $diagIdentity = "$($parsed.acquire.'User Identity')"

    $joined = $Device.azureAdJoined -eq 'YES'

    # ---- PRT state
    if ($joined -and $sidKind -ne 'Local') {
        if (-not $prt.present) {
            $findings.Add((New-Finding 'StaleToken' 'Fail' 'No PRT for this user (AzureAdPrt: NO) on a joined device' 'AzureAdPrt : NO' 'dsregcmd SSO State' '' @('refresh-prt') $sid))
        } else {
            if ($expiry -and $expiry -lt $now) {
                $findings.Add((New-Finding 'StaleToken' 'Fail' 'The PRT has expired' ("AzureAdPrtExpiryTime {0:u}" -f $expiry) 'dsregcmd SSO State' '' @('refresh-prt') $sid))
            } elseif ($update -and ($now - $update).TotalHours -gt $StaleHours) {
                $findings.Add((New-Finding 'StaleToken' 'Warn' ('PRT not renewed for {0:N0} hours (normal renewal is ~4h while active)' -f ($now - $update).TotalHours) ("AzureAdPrtUpdateTime {0:u}" -f $update) 'dsregcmd SSO State' '' @('refresh-prt') $sid))
            }
        }
    }

    # ---- AcquirePrtDiagnostics / RefreshPrtDiagnostics
    foreach ($f in (Get-DiagFindings $parsed.acquire 'AcquirePrtDiagnostics' $prt $sid $ctx)) { $findings.Add($f) }
    foreach ($f in (Get-DiagFindings $parsed.refresh 'RefreshPrtDiagnostics' $prt $sid $ctx)) { $findings.Add($f) }

    # ---- UPN consistency
    if ($joined -and $sidKind -ne 'Local') {
        if (-not $whoamiUpn) {
            $findings.Add((New-Finding 'IncorrectUpn' 'Warn' 'whoami /upn returned no UPN for this user' "$($Payload.whoamiUpn)" 'whoami /upn' '' @() $sid))
        } elseif ($whoamiUpn -match '\.(local|lan|corp|internal|intra|localdomain|home)$') {
            $findings.Add((New-Finding 'IncorrectUpn' 'Fail' 'The UPN suffix is not internet-routable, so Entra cannot discover the realm' $whoamiUpn 'whoami /upn' '' @() $sid))
        }
        $names = @(@($whoamiUpn, $windowsUpn, $diagIdentity) | Where-Object { $_ -and $_ -match '@' } | ForEach-Object { $_.ToLower() } | Select-Object -Unique)
        if ($names.Count -gt 1) {
            $findings.Add((New-Finding 'IncorrectUpn' 'Fail' 'Windows is using more than one UPN for this user (typically a UPN change without a sign-out)' ('whoami /upn={0}; CloudAP cache={1}; PRT attempt identity={2}' -f $whoamiUpn, $windowsUpn, $diagIdentity) 'UPN comparison' '' @() $sid))
        }
        if ($Realm -and $Realm.nameSpaceType -eq 'Unknown') {
            $findings.Add((New-Finding 'IncorrectUpn' 'Fail' 'Entra does not recognise the UPN suffix (userrealm NameSpaceType: Unknown)' $whoamiUpn 'userrealm lookup' '' @() $sid))
        }
    }

    # ---- WAM
    $wamSet = Get-DsregValue $parsed 'WamDefaultSet'
    $wamAuth = Get-DsregValue $parsed 'WamDefaultAuthority'
    if ($joined -and $prt.present) {
        if ($wamSet -eq 'NO') {
            $findings.Add((New-Finding 'WamInconsistency' 'Warn' 'PRT present but Web Account Manager has no default account (WamDefaultSet: NO)' 'WamDefaultSet : NO' 'dsregcmd User State' '' @('start-tokenbroker', 'reregister-broker', 'refresh-prt') $sid))
        } elseif ($wamSet -eq 'YES' -and $wamAuth -and $wamAuth -ne 'organizations') {
            $findings.Add((New-Finding 'WamInconsistency' 'Warn' "WAM default authority is '$wamAuth' instead of 'organizations'" "WamDefaultAuthority : $wamAuth" 'dsregcmd User State' '' @('reregister-broker') $sid))
        }
    }
    if ($Payload.brokerPlugin -and $Payload.brokerPlugin.present -eq $false) {
        $findings.Add((New-Finding 'WamInconsistency' 'Fail' 'The Microsoft.AAD.BrokerPlugin package is not registered for this user' 'Get-AppxPackage Microsoft.AAD.BrokerPlugin returned nothing' 'AppX' '' @('reregister-broker', 'refresh-prt') $sid))
    } elseif ($Payload.brokerPlugin -and "$($Payload.brokerPlugin.status)" -and "$($Payload.brokerPlugin.status)" -ne 'Ok') {
        $findings.Add((New-Finding 'WamInconsistency' 'Fail' "AAD.BrokerPlugin package status is '$($Payload.brokerPlugin.status)'" 'Get-AppxPackage status' 'AppX' '' @('reregister-broker', 'refresh-prt') $sid))
    }
    $workIds = @($Payload.officeIdentities | Where-Object { $_.provider -match '(?i)adal|orgid|aad' } | ForEach-Object { "$($_.email)".ToLower() })
    if ($whoamiUpn -and $workIds.Count -and ($workIds -notcontains $whoamiUpn.ToLower())) {
        $findings.Add((New-Finding 'WamInconsistency' 'Warn' 'Office is signed in with a different work account than Windows' ('Windows: {0}; Office: {1}' -f $whoamiUpn, ($workIds -join ', ')) 'Office identity' '' @() $sid))
    }

    # ---- SID
    if ($Device.domainJoined -eq 'YES' -and $joined -and $sidKind -eq 'ActiveDirectory (other domain)') {
        $findings.Add((New-Finding 'UserSidMissing' 'Info' 'User account is from a different AD domain than the device (expected in multi-domain forests)' ('user {0} / device domain {1}' -f $sid, $Device.sids.domainSid) 'SID comparison' '' @() $sid))
    }
    if ($joined -and $sidKind -ne 'Local' -and -not $windowsUpn -and $prt.present -eq $false) {
        $findings.Add((New-Finding 'UserSidMissing' 'Warn' 'No CloudAP identity-cache entry exists for this user SID' "IdentityStore\Cache\$sid" 'CloudAP cache' '' @() $sid))
    }

    # ---- Transactions and Operational errors that belong to this user
    $upnSet = @(@($whoamiUpn, $windowsUpn, $diagIdentity) | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
    $diagCorr = @(@("$($parsed.acquire.'Correlation ID')", "$($parsed.refresh.'Correlation ID')") | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
    $mine = @($Transactions | Where-Object {
        $t = $_
        ($t.userSids -contains $sid) -or (@($t.upns | Where-Object { $upnSet -contains $_ }).Count -gt 0) -or
        (@($t.correlationIds | Where-Object { $diagCorr -contains $_ }).Count -gt 0) -or
        ($SingleUser -and $t.userSids.Count -eq 0 -and $t.upns.Count -eq 0)
    })
    foreach ($t in ($mine | Where-Object { $_.outcome -eq 'Failed' })) {
        $tf = @(Invoke-Rules ("$($t.evidence) $($t.errorCodes -join ' ')") "AAD Analytic transaction #$($t.index)" (@($t.correlationIds) | Select-Object -First 1) $sid $ctx)
        foreach ($f in $tf) { $f.transaction = $t.index; $findings.Add($f) }
        $t.categories = @($tf | ForEach-Object { $_.category } | Select-Object -Unique)
    }
    # Diagnostics findings point at the transaction carrying the same Correlation ID.
    foreach ($f in $findings) {
        if ($f.correlationId -and -not $f.transaction) {
            $tx = $Transactions | Where-Object { $_.correlationIds -contains $f.correlationId } | Select-Object -First 1
            if ($tx) { $f.transaction = $tx.index }
        }
    }
    $opMine = @($Operational | Where-Object {
        $_.level -le 3 -and (($_.userSid -eq $sid) -or (@(Get-Upns $_.text | Where-Object { $upnSet -contains $_ }).Count -gt 0) -or
        ($SingleUser -and (-not $_.userSid -or $_.userSid -eq 'S-1-5-18')))
    } | Select-Object -Last 40)
    foreach ($e in $opMine) {
        foreach ($f in (Invoke-Rules ("[{0}] {1}" -f $e.time.ToString('u'), $e.text) "AAD Operational event $($e.id)" ((Get-CorrelationIds $e.text) | Select-Object -First 1) $sid $ctx)) {
            # Events older than the last good PRT renewal are history, not the current fault.
            if ($prt.present -and $prt.updateTime -and $e.time -lt $prt.updateTime) { $f.severity = 'Info'; $f.repair = @() }
            $findings.Add($f)
        }
    }

    $findings = @(Select-UniqueFindings $findings)
    [pscustomobject][ordered]@{
        account           = $User.account
        sid               = $sid
        sidKind           = $sidKind
        sidDomain         = $(if ($sid -like 'S-1-5-21-*') { $sid -replace '-\d+$', '' } else { '' })
        sessionId         = $User.sessionId
        collected         = [bool]$Payload
        whoamiUpn         = $whoamiUpn
        windowsUpn        = $windowsUpn
        prt               = [ordered]@{
            AzureAdPrt           = $prtFlag
            AzureAdPrtUpdateTime = Get-DsregValue $parsed 'AzureAdPrtUpdateTime'
            AzureAdPrtExpiryTime = Get-DsregValue $parsed 'AzureAdPrtExpiryTime'
            ageHours             = $(if ($update) { [Math]::Round(($now - $update).TotalHours, 1) } else { $null })
            AzureAdPrtAuthority  = Get-DsregValue $parsed 'AzureAdPrtAuthority'
            EnterprisePrt        = Get-DsregValue $parsed 'EnterprisePrt'
            OnPremTgt            = Get-DsregValue $parsed 'OnPremTgt'
            CloudTgt             = Get-DsregValue $parsed 'CloudTgt'
        }
        acquirePrtDiagnostics = $parsed.acquire
        refreshPrtDiagnostics = $parsed.refresh
        wam               = [ordered]@{
            WamDefaultSet       = $wamSet
            WamDefaultAuthority = $wamAuth
            WamDefaultId        = Get-DsregValue $parsed 'WamDefaultId'
            WamDefaultGUID      = Get-DsregValue $parsed 'WamDefaultGUID'
            brokerPlugin        = $Payload.brokerPlugin
            officeIdentities    = @($Payload.officeIdentities)
        }
        NgcSet            = Get-DsregValue $parsed 'NgcSet'
        wininetProxy      = $Payload.wininet
        userRealm         = $Realm
        transactions      = @($mine | ForEach-Object { $_.index })
        findings          = $findings
        primaryCategory   = (Get-Primary $findings)
    }
}

function Select-UniqueFindings($Findings) {
    $seen = @{}
    foreach ($f in ($Findings | Sort-Object { @{ Fail = 0; Warn = 1; Info = 2 }[$_.severity] })) {
        $k = '{0}|{1}|{2}' -f $f.category, $f.source, $f.title
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $f
    }
}

function Get-Primary($Findings) {
    foreach ($sev in 'Fail', 'Warn') {
        $hit = @($Findings | Where-Object { $_.severity -eq $sev }) | Sort-Object { $script:Categories[$_.category].rank } | Select-Object -First 1
        if ($hit) { return $hit.category }
    }
    return ''
}

# =========================================================================================== main
function Invoke-Main {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        # dsregcmd, the CloudAP registry cache and the task scheduler all need the 64-bit view.
        $native = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $native) {
            $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
            foreach ($kv in $script:BoundParams.GetEnumerator()) {
                if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $relaunch += "-$($kv.Key)" } }
                else { $relaunch += "-$($kv.Key)"; $relaunch += "$($kv.Value)" }
            }
            & $native @relaunch
            exit $LASTEXITCODE
        }
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $isSystem = Test-IsSystem
    $nowUtc = (Get-Date).ToUniversalTime()
    $since = $nowUtc.AddHours(-$HoursBack)
    $gaps = New-Object System.Collections.Generic.List[string]
    $deviceFindings = New-Object System.Collections.Generic.List[object]
    Initialize-SecureFolder $ReportPath

    # ---- device state (identical in every context)
    $sysDsreg = ConvertFrom-DsregStatus ((& dsregcmd.exe /status 2>&1) -join "`n")
    $device = [ordered]@{
        computer         = $env:COMPUTERNAME
        azureAdJoined    = Get-DsregValue $sysDsreg 'AzureAdJoined'
        domainJoined     = Get-DsregValue $sysDsreg 'DomainJoined'
        enterpriseJoined = Get-DsregValue $sysDsreg 'EnterpriseJoined'
        joinType         = ''
        tenantName       = Get-DsregValue $sysDsreg 'TenantName'
        tenantId         = Get-DsregValue $sysDsreg 'TenantId'
        deviceId         = Get-DsregValue $sysDsreg 'DeviceId'
        deviceAuthStatus = Get-DsregValue $sysDsreg 'DeviceAuthStatus'
        tpmProtected     = Get-DsregValue $sysDsreg 'TpmProtected'
        deviceCertExpiry = ''
        sids             = Get-DomainSids
        joinDiagnostics  = $(if ($sysDsreg.sections.Contains('Diagnostic Data')) { $sysDsreg.sections['Diagnostic Data'] } else { $null })
    }
    $device.joinType = if ($device.azureAdJoined -eq 'YES' -and $device.domainJoined -eq 'YES') { 'Microsoft Entra hybrid joined' }
        elseif ($device.azureAdJoined -eq 'YES') { 'Microsoft Entra joined' }
        elseif ($device.domainJoined -eq 'YES') { 'Domain joined only' }
        else { 'Not joined' }
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | Where-Object { $_.Issuer -match 'MS-Organization-Access' } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
        if ($cert) { $device.deviceCertExpiry = $cert.NotAfter.ToUniversalTime().ToString('o') }
    } catch { }

    $inScope = $device.azureAdJoined -eq 'YES' -or $device.domainJoined -eq 'YES'
    if ($device.domainJoined -eq 'YES' -and $device.azureAdJoined -ne 'YES') {
        $deviceFindings.Add((New-Finding 'DeviceJoin' 'Fail' 'Domain joined but not Entra hybrid joined - no PRT can be issued' 'AzureAdJoined : NO, DomainJoined : YES' 'dsregcmd Device State' '' @('hybrid-join-task')))
    }
    if ($device.azureAdJoined -eq 'YES' -and $device.deviceAuthStatus -and $device.deviceAuthStatus -ne 'SUCCESS') {
        $deviceFindings.Add((New-Finding 'DeviceJoin' 'Fail' 'Device authentication fails - the device object is probably disabled or deleted in Entra' "DeviceAuthStatus : $($device.deviceAuthStatus)" 'dsregcmd Device State' '' (Get-RepairFor 'DeviceJoin' '' $device)))
    }
    if ($device.azureAdJoined -eq 'YES' -and -not $device.deviceCertExpiry) {
        $deviceFindings.Add((New-Finding 'DeviceJoin' 'Fail' 'No MS-Organization-Access device certificate in LocalMachine\My' 'certificate missing' 'Certificate store' '' (Get-RepairFor 'DeviceJoin' '' $device)))
    } elseif ($device.deviceCertExpiry -and [datetime]$device.deviceCertExpiry -lt $nowUtc) {
        $deviceFindings.Add((New-Finding 'DeviceJoin' 'Fail' 'The device certificate has expired' $device.deviceCertExpiry 'Certificate store' '' (Get-RepairFor 'DeviceJoin' '' $device)))
    }
    if ($device.joinDiagnostics) {
        $jd = ($device.joinDiagnostics.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; '
        foreach ($f in (Invoke-Rules $jd 'dsregcmd Diagnostic Data' '' '' $device)) { if ($f.category -eq 'DeviceJoin') { $deviceFindings.Add($f) } }
    }

    # ---- services
    $services = [ordered]@{}
    foreach ($name in 'TokenBroker', 'NgcSvc', 'KeyIso', 'wlidsvc') {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        $start = ''
        try { $start = (Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop).StartMode } catch { }
        $services[$name] = [ordered]@{ status = $(if ($svc) { "$($svc.Status)" } else { 'Missing' }); startMode = $start }
    }
    if ($services.TokenBroker.startMode -eq 'Disabled') {
        $deviceFindings.Add((New-Finding 'WamInconsistency' 'Fail' 'The Web Account Manager service (TokenBroker) is disabled - no app can get a token silently' 'TokenBroker StartMode: Disabled' 'Services' '' @('start-tokenbroker')))
    }
    foreach ($name in 'NgcSvc', 'KeyIso') {
        if ($services[$name].status -ne 'Running' -and $services[$name].status -ne 'Missing') {
            $deviceFindings.Add((New-Finding 'WindowsHello' 'Fail' "$name is not running - the Hello/device key cannot sign" "$name : $($services[$name].status)" 'Services' '' @('start-ngc')))
        }
    }

    # ---- network
    $winHttp = Get-WinHttpProxy
    $probes = @()
    if (-not $SkipNetworkTests -and $inScope) {
        $probes = @('login.microsoftonline.com', 'device.login.microsoftonline.com', 'enterpriseregistration.windows.net' | ForEach-Object { Test-TlsEndpoint $_ $winHttp })
        foreach ($p in $probes) {
            if ($p.intercepted) {
                $deviceFindings.Add((New-Finding 'ProxyTls' 'Fail' "TLS to $($p.host) is re-signed by '$($p.issuer)' - TLS inspection is active" ('issuer={0}; root={1}; viaProxy={2}' -f $p.issuer, $p.root, $p.viaProxy) 'TLS probe (SYSTEM)'))
            } elseif (-not $p.tls) {
                $deviceFindings.Add((New-Finding 'ProxyTls' 'Fail' "SYSTEM cannot complete TLS to $($p.host)" ('{0}; WinHTTP proxy: {1}' -f $p.error, $(if ($winHttp.direct) { 'direct' } else { $winHttp.server })) 'TLS probe (SYSTEM)'))
            } elseif ($p.policyErrors -and $p.policyErrors -ne 'None') {
                $deviceFindings.Add((New-Finding 'ProxyTls' 'Fail' "Certificate for $($p.host) does not validate ($($p.policyErrors))" $p.issuer 'TLS probe (SYSTEM)'))
            }
        }
    }

    # ---- event logs
    $analyticInfo = [ordered]@{ enabled = $null; enabledByThisRun = $false; maxSizeBytes = $null; fileSizeBytes = $null; readOk = $false; events = 0; error = '' }
    try {
        $cfg = Get-WinEvent -ListLog $script:AnalyticLog -ErrorAction Stop
        $analyticInfo.enabled = $cfg.IsEnabled
        $analyticInfo.maxSizeBytes = $cfg.MaximumSizeInBytes
        $analyticInfo.fileSizeBytes = $cfg.FileSize
        if (-not $cfg.IsEnabled -and -not $NoLogChanges) {
            & wevtutil.exe sl $script:AnalyticLog /e:true /q:true /ms:33554432 2>&1 | Out-Null
            $analyticInfo.enabledByThisRun = ($LASTEXITCODE -eq 0)
        }
    } catch { $analyticInfo.error = $_.Exception.Message }
    $analytic = @()
    if ($analyticInfo.enabled) {
        try { $analytic = @(Get-AadEvents $script:AnalyticLog $since 30000 -Analytic); $analyticInfo.readOk = $true }
        catch {
            if (Test-NoEvents $_) { $analyticInfo.readOk = $true }
            elseif (-not $NoLogChanges) {
                # Some builds refuse to read an enabled direct (Analytic) channel. Disable it for the
                # read and always switch it back on afterwards.
                try {
                    & wevtutil.exe sl $script:AnalyticLog /e:false /q:true 2>&1 | Out-Null
                    try { $analytic = @(Get-AadEvents $script:AnalyticLog $since 30000 -Analytic); $analyticInfo.readOk = $true }
                    catch { if (Test-NoEvents $_) { $analyticInfo.readOk = $true } else { $analyticInfo.error = $_.Exception.Message } }
                } finally { & wevtutil.exe sl $script:AnalyticLog /e:true /q:true 2>&1 | Out-Null }
            } else { $analyticInfo.error = $_.Exception.Message }
        }
        $analyticInfo.events = $analytic.Count
        if ($analyticInfo.error) { $gaps.Add("AAD Analytic channel unreadable: $($analyticInfo.error)") }
    } else {
        $gaps.Add($(if ($analyticInfo.enabledByThisRun) { 'AAD Analytic channel was disabled; enabled now - transactions appear from the next run' } else { 'AAD Analytic channel is disabled - no 1006/1007 transactions to correlate' }))
    }
    $operational = @()
    try { $operational = @(Get-AadEvents $script:OperationalLog $since 3000) }
    catch { if (-not (Test-NoEvents $_)) { $gaps.Add("AAD Operational log unreadable: $($_.Exception.Message)") } }
    $transactions = @(Group-AadTransactions $analytic $operational $TransactionStartId $TransactionEndId)

    # ---- users
    $users = @()
    $interactive = @()
    if ($isSystem) { $interactive = @(Get-InteractiveUsers) }
    else {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        $interactive = @([pscustomobject]@{ account = $me.Name; sid = $me.User.Value; sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId })
    }
    if ($inScope) {
        foreach ($u in $interactive) {
            $payload = $null
            try { $payload = Invoke-AsUser $u @{ action = 'collect' } $ReportPath } catch { $gaps.Add("user context collection failed for $($u.account): $($_.Exception.Message)") }
            if (-not $payload) { $gaps.Add("no user-context data for $($u.account) - PRT state could not be read for this user") }
            $realm = $null
            if (-not $SkipNetworkTests -and $payload -and "$($payload.whoamiUpn)" -match '@') { $realm = Get-UserRealm "$($payload.whoamiUpn)".Trim() }
            $users += Get-UserAnalysis $u $payload $device $transactions $operational ($interactive.Count -eq 1) $realm
        }
    }

    # ---- verdict
    $all = @(@($deviceFindings) + @($users | ForEach-Object { $_.findings }))
    $blocking = @($all | Where-Object { $_.severity -eq 'Fail' -or ($_.severity -eq 'Warn' -and @($_.repair).Count -gt 0) })
    $primary = Get-Primary $all
    $status = if (-not $inScope) { 'NotApplicable' } elseif ($blocking.Count) { 'Unhealthy' } elseif (@($all | Where-Object { $_.severity -eq 'Warn' }).Count) { 'Warning' } else { 'Healthy' }
    if ($inScope -and $interactive.Count -eq 0 -and $status -eq 'Healthy') { $status = 'NoUser' }

    $report = [ordered]@{
        schema         = 'endpointweekly.prt-sso/1'
        scriptVersion  = $script:Version
        generatedUtc   = $nowUtc.ToString('o')
        runAs          = $(if ($isSystem) { 'SYSTEM' } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name })
        hoursBack      = $HoursBack
        anonymised     = [bool]$Anonymise
        verdict        = [ordered]@{
            status          = $status
            primaryCategory = $primary
            primaryName     = $(if ($primary) { $script:Categories[$primary].name } else { '' })
            guidance        = $(if ($primary) { $script:Categories[$primary].fix } else { '' })
            categories      = @($all | Where-Object { $_.severity -ne 'Info' } | ForEach-Object { $_.category } | Select-Object -Unique)
            affectedUsers   = @($users | Where-Object { @($_.findings | Where-Object { $_.severity -eq 'Fail' }).Count } | ForEach-Object { $_.sid })
        }
        device         = $device
        services       = $services
        network        = [ordered]@{ winHttpProxy = $winHttp; tlsProbes = @($probes) }
        analyticLog    = $analyticInfo
        deviceFindings = @($deviceFindings)
        users          = @($users)
        transactions   = @($transactions)
        operationalErrors = @($operational | Where-Object { $_.level -le 2 } | Select-Object -Last 50 | ForEach-Object {
            [pscustomobject]@{ time = $_.time.ToString('o'); id = $_.id; userSid = $_.userSid; codes = @(Get-EvidenceCodes $_.text); correlationIds = @(Get-CorrelationIds $_.text); text = (Limit-Text $_.text 600) } })
        gaps           = @($gaps)
        categoryCatalog = $script:Categories
    }

    if ($Anonymise) { Protect-Report $report }
    $json = $report | ConvertTo-Json -Depth 10
    $latest = Join-Path $ReportPath 'PrtSso-latest.json'
    try {
        Set-Content -LiteralPath $latest -Value $json -Encoding UTF8 -ErrorAction Stop
        Copy-Item -LiteralPath $latest -Destination (Join-Path $ReportPath ('PrtSso-{0}-{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force
        Get-ChildItem -LiteralPath $ReportPath -Filter 'PrtSso-*-*.json' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 10 | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { $gaps.Add("could not write report: $($_.Exception.Message)") }

    if (-not $isSystem -or $ShowReport) { Write-ConsoleReport $report $latest }

    # ---- Intune output: one line, under 2048 characters
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add($status.ToUpper())
    if ($primary) { $parts.Add("primary=$($script:Categories[$primary].name)") }
    foreach ($u in $users) {
        $top = @($u.findings | Where-Object { $_.severity -eq 'Fail' } | Sort-Object { $script:Categories[$_.category].rank } | Select-Object -First 1)
        $code = if ($top) { (@(Get-EvidenceCodes $top[0].evidence) | Select-Object -First 1) } else { '' }
        $parts.Add(('user={0} upn={1} PRT={2} age={3}h {4}{5}{6}' -f (Hide-Text $u.account 'account'), (Hide-Text $u.whoamiUpn 'upn'), $u.prt.AzureAdPrt, $(if ($null -ne $u.prt.ageHours) { $u.prt.ageHours } else { '?' }),
            $(if ($u.primaryCategory) { "cat=$($u.primaryCategory) " } else { '' }), $(if ($code) { "code=$code " } else { '' }),
            $(if ($top -and $top[0].correlationId) { "corr=$(Hide-Text $top[0].correlationId)" } else { '' })).Trim())
    }
    $parts.Add("join=$($device.joinType)")
    if ($interactive.Count -eq 0) { $parts.Add('no interactive user (PRT is per user)') }
    if ($transactions.Count) { $parts.Add(('tx={0} failed={1}' -f $transactions.Count, @($transactions | Where-Object { $_.outcome -eq 'Failed' }).Count)) }
    if ($gaps.Count) { $parts.Add("gaps=$($gaps.Count)") }
    $line = $parts -join ' | '
    if ($line.Length -gt 2000) { $line = $line.Substring(0, 1997) + '...' }
    Write-Output $line

    if ($status -eq 'Unhealthy') { exit 1 }
    exit 0
}

function Protect-Report($Report) {
    $Report.device.deviceId = Hide-Text $Report.device.deviceId
    $Report.device.tenantId = Hide-Text $Report.device.tenantId
    $Report.device.sids.domainSid = Hide-Text $Report.device.sids.domainSid 'sid'
    $Report.device.sids.localSid = Hide-Text $Report.device.sids.localSid 'sid'
    $Report.verdict.affectedUsers = @($Report.verdict.affectedUsers | ForEach-Object { Hide-Text $_ 'sid' })
    foreach ($u in $Report.users) {
        $u.account = Hide-Text $u.account 'account'
        $u.sid = Hide-Text $u.sid 'sid'
        $u.sidDomain = Hide-Text $u.sidDomain 'sid'
        $u.whoamiUpn = Hide-Text $u.whoamiUpn 'upn'
        $u.windowsUpn = Hide-Text $u.windowsUpn 'upn'
        foreach ($d in @($u.acquirePrtDiagnostics, $u.refreshPrtDiagnostics)) {
            if ($d) { foreach ($k in @($d.Keys)) { $d[$k] = Hide-Evidence "$($d[$k])" } }
        }
        $u.wam.officeIdentities = @($u.wam.officeIdentities | ForEach-Object { [ordered]@{ email = Hide-Text "$($_.email)" 'upn'; provider = $_.provider } })
        $u.userRealm = $null
    }
    foreach ($f in @($Report.deviceFindings) + @($Report.users | ForEach-Object { $_.findings })) {
        $f.evidence = Hide-Evidence $f.evidence; $f.title = Hide-Evidence $f.title
        $f.correlationId = Hide-Text $f.correlationId; $f.userSid = Hide-Text $f.userSid 'sid'
    }
    foreach ($t in $Report.transactions) {
        $t.evidence = Hide-Evidence $t.evidence
        $t.correlationIds = @($t.correlationIds | ForEach-Object { '<masked>' })
        $t.userSids = @($t.userSids | ForEach-Object { Hide-Text $_ 'sid' })
        $t.upns = @($t.upns | ForEach-Object { Hide-Text $_ 'upn' })
        foreach ($e in $t.timeline) { $e.text = Hide-Evidence $e.text }
    }
    foreach ($e in $Report.operationalErrors) { $e.text = Hide-Evidence $e.text; $e.userSid = Hide-Text $e.userSid 'sid'; $e.correlationIds = @($e.correlationIds | ForEach-Object { '<masked>' }) }
}

function Write-ConsoleReport($Report, [string]$Path) {
    $colour = @{ Healthy = 'Green'; Warning = 'Yellow'; Unhealthy = 'Red'; NotApplicable = 'Gray'; NoUser = 'Gray' }
    Write-Host ''
    Write-Host ("PRT / WAM / SSO analysis - {0}  ({1})" -f $Report.device.computer, $Report.device.joinType) -ForegroundColor White
    Write-Host ('-' * 72) -ForegroundColor DarkGray
    Write-Host ("Verdict : {0}{1}" -f $Report.verdict.status, $(if ($Report.verdict.primaryName) { " - $($Report.verdict.primaryName)" } else { '' })) -ForegroundColor $colour[$Report.verdict.status]
    if ($Report.verdict.guidance) { Write-Host ("          {0}" -f $Report.verdict.guidance) -ForegroundColor Gray }
    Write-Host ("Device  : DeviceAuthStatus={0}  cert expiry={1}  domain SID={2}" -f $Report.device.deviceAuthStatus, $Report.device.deviceCertExpiry, $Report.device.sids.domainSid)
    Write-Host ("AAD log : Analytic enabled={0} events={1}  transactions={2}" -f $Report.analyticLog.enabled, $Report.analyticLog.events, @($Report.transactions).Count)
    foreach ($f in $Report.deviceFindings) { Write-FindingLine $f }
    foreach ($u in $Report.users) {
        Write-Host ''
        Write-Host ("User    : {0}  [{1}]  SID {2}" -f $u.account, $u.sidKind, $u.sid) -ForegroundColor Cyan
        Write-Host ("  whoami /upn={0}  Windows UPN={1}" -f $u.whoamiUpn, $u.windowsUpn)
        Write-Host ("  AzureAdPrt={0}  updated={1}  expires={2}  age={3}h" -f $u.prt.AzureAdPrt, $u.prt.AzureAdPrtUpdateTime, $u.prt.AzureAdPrtExpiryTime, $u.prt.ageHours)
        Write-Host ("  WamDefaultSet={0}  WamDefaultAuthority={1}  NgcSet={2}" -f $u.wam.WamDefaultSet, $u.wam.WamDefaultAuthority, $u.NgcSet)
        foreach ($d in @(@('Acquire', $u.acquirePrtDiagnostics), @('Refresh', $u.refreshPrtDiagnostics))) {
            if ($d[1] -and $d[1].state -eq 'PRESENT') {
                Write-Host ("  {0}: status={1} cred={2} http={3}/{4} server={5} corr={6}" -f $d[0], $d[1].'Attempt Status', $d[1].'Credential Type', $d[1].'HTTP Error', $d[1].'HTTP status', $d[1].'Server Error Code', $d[1].'Correlation ID')
                if ($d[1].'Server Error Description') { Write-Host ("           {0}" -f (Limit-Text $d[1].'Server Error Description' 160)) -ForegroundColor Gray }
            }
        }
        foreach ($f in $u.findings) { Write-FindingLine $f }
    }
    foreach ($g in $Report.gaps) { Write-Host ("  [gap]  {0}" -f $g) -ForegroundColor DarkYellow }
    Write-Host ''
    Write-Host ("Report  : {0}  (open it in prt-report-viewer.html)" -f $Path) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-FindingLine($F) {
    $c = @{ Fail = 'Red'; Warn = 'Yellow'; Info = 'DarkGray' }[$F.severity]
    $tx = if ($F.transaction) { " [tx #$($F.transaction)]" } else { '' }
    Write-Host ("  [{0}] {1}: {2}{3}" -f $F.severity.ToUpper(), $F.categoryName, $F.title, $tx) -ForegroundColor $c
}

# Dot-sourcing (". .\Detect-PrtSsoHealth.ps1") loads the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
