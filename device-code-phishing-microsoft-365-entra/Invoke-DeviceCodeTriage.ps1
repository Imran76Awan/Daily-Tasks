<#
.SYNOPSIS
    Local endpoint triage for suspected device-code phishing / OAuth token abuse.

.DESCRIPTION
    Read-only triage script. Collects and reports on the local artifacts that
    correlate with a device-code sign-in on this machine:
      - dsregcmd /status (device join + Primary Refresh Token state)
      - Microsoft-Windows-AAD/Operational event log (token broker activity)
      - WAM Token Broker cache folder (timestamps only - files are DPAPI-protected,
        this script does NOT decrypt or read token contents)
      - AAD Broker Plugin package folder + related registry key health
      - Web Account Manager / Microsoft Account Sign-in Assistant service state
      - Edge / Chrome history for visits to microsoft.com/devicelogin

    This script does NOT prove or disprove compromise on its own. The
    authoritative record is the Entra ID sign-in log (AuthenticationProtocol
    == "deviceCode") for the affected user. Treat this output as supporting
    timeline evidence to correlate against that log - not a verdict.

.NOTES
    Run as the affected user (not SYSTEM/elevated-only), so HKCU and
    %LOCALAPPDATA% resolve to the correct profile. Elevation is only needed
    for the registry permission check; the script will note if it's missing.
    Makes no changes to the system, the registry, or any files.

.PARAMETER LookbackDays
    How many days back to search the AAD Operational event log. Default 7.

.PARAMETER OutputPath
    Where to write the plain-text report. Defaults to the user's Desktop.

.EXAMPLE
    .\Invoke-DeviceCodeTriage.ps1 -LookbackDays 14
#>

[CmdletBinding()]
param(
    [int]$LookbackDays = 7,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DeviceCodeTriage_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
)

$report = New-Object System.Collections.Generic.List[string]

function Add-Line { param([string]$Text) $report.Add($Text); Write-Host $Text }
function Add-Section {
    param([string]$Title)
    Add-Line ""
    Add-Line ("=" * 70)
    Add-Line "  $Title"
    Add-Line ("=" * 70)
}

Add-Line "Device Code Phishing - Local Endpoint Triage"
Add-Line "Host: $env:COMPUTERNAME   User: $env:USERNAME   Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Line "Lookback window: $LookbackDays day(s)"
Add-Line "Reminder: cross-check every finding below against the Entra ID sign-in log for this user."

# ---------------------------------------------------------------------------
# 1. Device join / PRT state
# ---------------------------------------------------------------------------
Add-Section "1. dsregcmd /status - device join and PRT state"
try {
    $dsreg = dsregcmd /status 2>&1
    $keys = 'AzureAdJoined','EnterpriseJoined','DomainJoined','WorkplaceJoined',
            'AzureAdPrt','AzureAdPrtUpdateTime','TenantId','DeviceId'
    foreach ($line in $dsreg) {
        foreach ($k in $keys) {
            if ($line -match "^\s*$k\s*:") { Add-Line ($line.Trim()) }
        }
    }
    Add-Line ""
    Add-Line "Why it matters: AzureAdPrtUpdateTime shows when this device's Primary Refresh"
    Add-Line "Token last refreshed. A refresh timestamp that doesn't line up with a normal"
    Add-Line "sign-in the user remembers is worth asking about - but note a PRT refresh here"
    Add-Line "reflects THIS device's session, not the attacker's separate client."
} catch {
    Add-Line "dsregcmd not available or failed to run: $_"
}

# ---------------------------------------------------------------------------
# 2. AAD Operational event log
# ---------------------------------------------------------------------------
Add-Section "2. Microsoft-Windows-AAD/Operational event log"
try {
    $start = (Get-Date).AddDays(-$LookbackDays)
    $events = Get-WinEvent -LogName "Microsoft-Windows-AAD/Operational" -ErrorAction Stop |
        Where-Object { $_.TimeCreated -ge $start }

    if (-not $events) {
        Add-Line "No events found in the last $LookbackDays day(s)."
    } else {
        Add-Line "Found $($events.Count) event(s). Showing Event IDs of interest:"
        Add-Line ""
        # 1006/1007 = token acquisition success/failure, 1098 = token broker failure
        $interesting = $events | Where-Object { $_.Id -in 1006,1007,1098 }
        if ($interesting) {
            $interesting | Sort-Object TimeCreated -Descending | Select-Object -First 25 | ForEach-Object {
                Add-Line ("[{0}] EventID {1} - {2}" -f $_.TimeCreated, $_.Id, ($_.Message -split "`n")[0])
            }
        } else {
            Add-Line "None of Event ID 1006 / 1007 / 1098 in this window."
        }
        Add-Line ""
        Add-Line "1006/1007 = token acquisition success/failure. 1098 = token broker"
        Add-Line "operation failed (often benign - see Microsoft Learn - but worth noting"
        Add-Line "the timestamp if it clusters around a reported phishing click)."
    }
} catch {
    Add-Line "Could not read the AAD Operational log: $($_.Exception.Message)"
    Add-Line "(This log may need to be enabled: wevtutil sl Microsoft-Windows-AAD/Operational /e:true)"
}

# ---------------------------------------------------------------------------
# 3. WAM Token Broker cache - timestamps only, never contents
# ---------------------------------------------------------------------------
Add-Section "3. WAM Token Broker cache (timestamps only)"
$brokerCache = "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"
if (Test-Path $brokerCache) {
    $files = Get-ChildItem $brokerCache -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($files) {
        Add-Line "Path: $brokerCache"
        Add-Line ""
        $files | Select-Object -First 15 | ForEach-Object {
            Add-Line ("{0}  {1,10:N0} bytes  {2}" -f $_.LastWriteTime, $_.Length, $_.Name)
        }
        Add-Line ""
        Add-Line "These files are DPAPI-protected JSON blobs. This script deliberately does"
        Add-Line "NOT open or decrypt them. A newly-written file at the time of a reported"
        Add-Line "phishing click is a timeline correlator, not proof by itself."
    } else {
        Add-Line "Folder exists but is empty."
    }
} else {
    Add-Line "Path not found: $brokerCache"
}

# ---------------------------------------------------------------------------
# 4. AAD Broker Plugin package folder + registry health
# ---------------------------------------------------------------------------
Add-Section "4. AAD Broker Plugin (Microsoft.AAD.BrokerPlugin)"
$brokerPkg = "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
if (Test-Path $brokerPkg) {
    $lastWrite = (Get-Item $brokerPkg).LastWriteTime
    Add-Line "Package folder present: $brokerPkg"
    Add-Line "Last modified: $lastWrite"
} else {
    Add-Line "Package folder not found: $brokerPkg"
}

$regPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\PSR"
if (Test-Path $regPath) {
    Add-Line "Registry key present: $regPath"
} else {
    Add-Line "Registry key not found (only created after first broker use - absence is not an error): $regPath"
}
Add-Line ""
Add-Line "This key is normally a WAM plumbing detail (see Event ID 1098 troubleshooting"
Add-Line "docs). Included here for completeness if you're also chasing broken sign-in"
Add-Line "prompts on the same machine."

# ---------------------------------------------------------------------------
# 5. Relevant services
# ---------------------------------------------------------------------------
Add-Section "5. Identity-related services"
$svcNames = @{
    'TokenBroker' = 'Web Account Manager'
    'wlidsvc'     = 'Microsoft Account Sign-in Assistant'
}
foreach ($svc in $svcNames.Keys) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Add-Line ("{0,-30} {1,-12} StartType={2}" -f $svcNames[$svc], $s.Status, $s.StartType)
    } else {
        Add-Line ("{0,-30} not found on this system" -f $svcNames[$svc])
    }
}

# ---------------------------------------------------------------------------
# 6. Browser history - visits to the device login page
# ---------------------------------------------------------------------------
Add-Section "6. Browser history - microsoft.com/devicelogin visits"
$profiles = @(
    @{ Name = "Edge";   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" },
    @{ Name = "Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" }
)
foreach ($p in $profiles) {
    if (Test-Path $p.Path) {
        $tmp = Join-Path $env:TEMP "history_$($p.Name)_$(Get-Random).db"
        try {
            # History is locked while the browser is open - copy it first.
            Copy-Item $p.Path $tmp -ErrorAction Stop
            $hits = Select-String -Path $tmp -Pattern 'devicelogin' -SimpleMatch -ErrorAction SilentlyContinue
            if ($hits) {
                Add-Line "$($p.Name): $($hits.Count) match(es) for 'devicelogin' found in history file."
                Add-Line "  This is a raw string search on the SQLite file, not a parsed timestamp -"
                Add-Line "  open the file in a SQLite viewer against the 'urls' table for exact visit times,"
                Add-Line "  or use a proper history-parsing tool if this needs to hold up in an investigation."
            } else {
                Add-Line "$($p.Name): no match for 'devicelogin' in history file."
            }
        } catch {
            Add-Line "$($p.Name): could not read history (browser likely open, file locked). Close $($p.Name) and re-run to check this source."
        } finally {
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    } else {
        Add-Line "$($p.Name): history file not found for this profile."
    }
}

# ---------------------------------------------------------------------------
# Wrap up
# ---------------------------------------------------------------------------
Add-Section "Summary"
Add-Line "This report is local, supporting evidence only. Next steps:"
Add-Line "  1. Pull the Entra ID sign-in log for this user filtered on AuthenticationProtocol == 'deviceCode'."
Add-Line "  2. Line up any hits above against the timestamp of that sign-in."
Add-Line "  3. If a match is confirmed: revoke sessions, reset password, force MFA re-registration,"
Add-Line "     and check Exchange for new inbox rules and OAuth app consents for this user."

$report | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "`nReport written to: $OutputPath" -ForegroundColor Green
