<#
.SYNOPSIS
    Read-only diagnostic for a ConfigMgr client's Cloud Management Gateway (CMG) connectivity.

.DESCRIPTION
    This script does NOT change any configuration, certificate, registry value, or ConfigMgr
    client setting. It only reads existing client log files and performs basic outbound
    network reachability tests, then prints a summary so you can tell the difference between
    "the CMG cloud service is unreachable" and "the client can reach it but does not trust it
    / cannot validate its certificate revocation status" - which, per Microsoft's own CMG
    documentation, is the most common real-world cause of a device showing as not connected
    to CMG despite a healthy-looking CMG deployment.

    It inspects the following ConfigMgr client log files under %WINDIR%\CCM\Logs, all of which
    are documented in Microsoft's official Configuration Manager log file reference
    (https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files):

        - LocationServices.log   : client activity locating management points, software
                                    update points, and distribution points (this is where a
                                    CMG-published management point lookup shows up).
        - ClientLocation.log     : client site assignment tasks.
        - CcmMessaging.log       : client-to-management-point communication, including the
                                    policy request/response traffic that would traverse a CMG.

    It then runs Test-NetConnection against the supplied CMG fully-qualified domain name on
    TCP 443, and optionally against a CRL distribution point / OCSP responder URL if supplied,
    so you get an independent network-level signal alongside the log evidence.

    FLAGGED AS UNCERTAIN: exact wording and error codes inside CMG-related log lines vary by
    ConfigMgr client version and authentication model (PKI certificate vs. Microsoft Entra ID
    vs. site-issued token). This script searches for common, documented failure keywords
    (e.g. "CRL", "certificate", "0x87d00215", "failed to send", "MP", "CMG") rather than
    asserting a single canonical error string. Always read the matched log lines yourself
    before drawing a conclusion - do not rely on keyword matches alone.

.NOTES
    Author        : Imran Awan
    Blog post     : https://endpointweekly.com/blog/intune-cloud-management-gateway-cmg-overview-setup.html
    Read-only     : Yes. This script makes no changes to the device, registry, certificates,
                    or ConfigMgr client configuration.
    Requirements  : Run locally (or via remote PowerShell) on the Windows device you are
                    diagnosing. Requires the ConfigMgr client to be installed
                    (%WINDIR%\CCM\Logs must exist) for the log-inspection portion.
                    Network tests require outbound connectivity from the host running the
                    script - run it from the actual device experiencing the issue, not from
                    a jump box on a different network.
    Status        : Companion script for the linked blog post. The "real output" example
                    shown in the blog post is an honestly-labelled placeholder - it has not
                    yet been captured against a live device. This script has not yet been
                    pushed to a public repository.

.PARAMETER CMGFqdn
    The fully-qualified domain name of your CMG cloud service endpoint, e.g.
    "contoso.cloudapp.net" or a custom CMG domain name. Required.

.PARAMETER CrlUrl
    Optional. The CRL distribution point URL (or OCSP responder URL) referenced by your PKI
    client authentication certificate template, if you use PKI-based client authentication.
    If supplied, the script tests reachability of this URL as well. Skip this parameter if
    you authenticate clients via Microsoft Entra ID or Configuration Manager site-issued
    tokens, since CRL/OCSP reachability from the client is not part of that authentication
    path.

.PARAMETER LogPath
    Optional. Override the default ConfigMgr client log folder
    ("$env:WINDIR\CCM\Logs"). Useful if inspecting exported logs from another machine.

.PARAMETER LogLines
    Optional. Number of most recent lines to scan per log file. Default 500. Increase if the
    device has been failing for a long time and the relevant entries are further back.

.EXAMPLE
    .\Test-CMGClientConnectivity.ps1 -CMGFqdn "contoso.cloudapp.net"

    Runs the log inspection and a basic TCP 443 reachability test against the CMG endpoint.

.EXAMPLE
    .\Test-CMGClientConnectivity.ps1 -CMGFqdn "contoso.cloudapp.net" -CrlUrl "http://crl.contoso.com/pki/contoso-ca.crl" -LogLines 2000

    Also tests reachability of the PKI CRL distribution point, and scans a larger window of
    each log file.

.EXAMPLE
    .\Test-CMGClientConnectivity.ps1 -CMGFqdn "contoso.cloudapp.net" -LogPath "D:\ExportedLogs\CCM\Logs"

    Runs against log files exported from another device instead of the local CCM\Logs folder.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CMGFqdn,

    [Parameter(Mandatory = $false)]
    [string]$CrlUrl,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path -Path $env:WINDIR -ChildPath 'CCM\Logs'),

    [Parameter(Mandatory = $false)]
    [ValidateRange(50, 100000)]
    [int]$LogLines = 500
)

$ErrorActionPreference = 'Stop'

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ''
    Write-Host "==== $Title ====" -ForegroundColor Cyan
}

function Get-CmgLogFinding {
    param(
        [Parameter(Mandatory = $true)][string]$FullLogPath,
        [Parameter(Mandatory = $true)][string]$FriendlyName,
        [Parameter(Mandatory = $true)][int]$TailLines
    )

    $result = [ordered]@{
        LogName   = $FriendlyName
        Path      = $FullLogPath
        Found     = $false
        MatchCount = 0
        Matches   = @()
        Error     = $null
    }

    if (-not (Test-Path -LiteralPath $FullLogPath)) {
        $result.Error = "Log file not found at '$FullLogPath'. Confirm the ConfigMgr client is installed and this device has attempted a CMG connection recently."
        return [pscustomobject]$result
    }

    try {
        $tail = Get-Content -LiteralPath $FullLogPath -Tail $TailLines -ErrorAction Stop
    }
    catch {
        $result.Error = "Failed to read '$FullLogPath': $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $keywords = @('CRL', 'certificate', 'CMG', '0x87d00215', 'failed to send', 'revocation', 'MP', 'HTTP status')
    $pattern = ($keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

    $matchedLines = $tail | Where-Object { $_ -match $pattern }

    $result.Found = ($matchedLines.Count -gt 0)
    $result.MatchCount = $matchedLines.Count
    $result.Matches = $matchedLines | Select-Object -Last 15

    return [pscustomobject]$result
}

Write-SectionHeader -Title 'CMG Client Connectivity Diagnostic (read-only)'
Write-Host "Target CMG FQDN : $CMGFqdn"
Write-Host "Log folder      : $LogPath"
Write-Host "Tail lines/log  : $LogLines"
Write-Host "Run time (UTC)  : $((Get-Date).ToUniversalTime().ToString('u'))"

# ---------------------------------------------------------------------------
# 1. Client-side log inspection (read-only)
# ---------------------------------------------------------------------------
Write-SectionHeader -Title 'Step 1 of 3 - ConfigMgr client log inspection'

$logsToCheck = @(
    @{ File = 'LocationServices.log'; Friendly = 'LocationServices.log (MP/SUP/DP location)' }
    @{ File = 'ClientLocation.log';   Friendly = 'ClientLocation.log (site assignment)' }
    @{ File = 'CcmMessaging.log';     Friendly = 'CcmMessaging.log (client-to-MP messaging)' }
)

$logFindings = @()

foreach ($entry in $logsToCheck) {
    $fullPath = Join-Path -Path $LogPath -ChildPath $entry.File
    $finding = Get-CmgLogFinding -FullLogPath $fullPath -FriendlyName $entry.Friendly -TailLines $LogLines
    $logFindings += $finding

    if ($finding.Error) {
        Write-Host "[WARN] $($finding.LogName): $($finding.Error)" -ForegroundColor Yellow
        continue
    }

    if ($finding.Found) {
        Write-Host "[FOUND] $($finding.LogName): $($finding.MatchCount) matching line(s) in the last $LogLines lines." -ForegroundColor Yellow
        Write-Host "        Most recent matches:" -ForegroundColor Yellow
        foreach ($line in $finding.Matches) {
            Write-Host "          $line" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[OK] $($finding.LogName): no CRL/certificate/CMG-related keywords found in the last $LogLines lines." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 2. Network reachability to the CMG endpoint (read-only)
# ---------------------------------------------------------------------------
Write-SectionHeader -Title 'Step 2 of 3 - Network reachability to CMG endpoint (TCP 443)'

$cmgReachable = $false
try {
    $cmgTest = Test-NetConnection -ComputerName $CMGFqdn -Port 443 -InformationLevel Detailed -ErrorAction Stop
    $cmgReachable = [bool]$cmgTest.TcpTestSucceeded

    if ($cmgReachable) {
        Write-Host "[OK] TCP 443 to '$CMGFqdn' succeeded from this device." -ForegroundColor Green
    }
    else {
        Write-Host "[FAIL] TCP 443 to '$CMGFqdn' did not succeed from this device." -ForegroundColor Red
    }
    Write-Host "        Resolved address : $($cmgTest.RemoteAddress)"
}
catch {
    Write-Host "[ERROR] Could not test connectivity to '$CMGFqdn': $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 3. Optional: CRL / OCSP reachability (read-only) - PKI client auth only
# ---------------------------------------------------------------------------
Write-SectionHeader -Title 'Step 3 of 3 - CRL/OCSP endpoint reachability (optional, PKI client auth only)'

$crlReachable = $null
if ([string]::IsNullOrWhiteSpace($CrlUrl)) {
    Write-Host "[SKIPPED] No -CrlUrl supplied. Skip this step if you authenticate clients via Microsoft Entra ID or site-issued tokens." -ForegroundColor DarkGray
}
else {
    try {
        $uri = [uri]$CrlUrl
        $crlHost = $uri.Host
        $crlPort = if ($uri.Port -gt 0) { $uri.Port } elseif ($uri.Scheme -eq 'https') { 443 } else { 80 }

        $crlTest = Test-NetConnection -ComputerName $crlHost -Port $crlPort -InformationLevel Detailed -ErrorAction Stop
        $crlReachable = [bool]$crlTest.TcpTestSucceeded

        if ($crlReachable) {
            Write-Host "[OK] Network path to CRL/OCSP host '$crlHost' on port $crlPort succeeded." -ForegroundColor Green
            Write-Host "     (This confirms basic network reachability only - it does not confirm the CRL/OCSP" -ForegroundColor DarkGray
            Write-Host "      response itself is valid or current. Verify that separately with your PKI team.)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "[FAIL] Network path to CRL/OCSP host '$crlHost' on port $crlPort did not succeed from this device." -ForegroundColor Red
            Write-Host "       If this device is off the corporate network, this is a strong candidate for why" -ForegroundColor Red
            Write-Host "       certificate revocation checking is failing and the client is being treated as untrusted." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[ERROR] Could not parse or test -CrlUrl '$CrlUrl': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-SectionHeader -Title 'Summary'

$anyLogFindings = ($logFindings | Where-Object { $_.Found }).Count -gt 0
$anyLogErrors   = ($logFindings | Where-Object { $_.Error }).Count -gt 0

Write-Host "CMG endpoint reachable (TCP 443)      : $cmgReachable"
if ($null -ne $crlReachable) {
    Write-Host "CRL/OCSP endpoint reachable            : $crlReachable"
}
Write-Host "CMG/certificate keywords found in logs : $anyLogFindings"
if ($anyLogErrors) {
    Write-Host "One or more log files could not be read - see [WARN] lines above." -ForegroundColor Yellow
}

Write-Host ''
Write-Host "This script is read-only. No configuration was changed on this device." -ForegroundColor DarkGray
Write-Host "For the full explanation of why CMG connectivity failures usually trace back to" -ForegroundColor DarkGray
Write-Host "certificate trust or CRL/OCSP reachability, see:" -ForegroundColor DarkGray
Write-Host "https://endpointweekly.com/blog/intune-cloud-management-gateway-cmg-overview-setup.html" -ForegroundColor DarkGray
