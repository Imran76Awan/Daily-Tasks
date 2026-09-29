<#
.SYNOPSIS
    Shows who created or changed an Intune policy and when, using the policy's own
    timestamps plus the Intune audit log.

.DESCRIPTION
    Answers the question you get asked the moment an unexpected policy turns up:
    "who made this, and when?"

    Two sources are combined:

      1. The policy object's own createdDateTime and lastModifiedDateTime. Always available,
         but tells you nothing about WHO.
      2. deviceManagement/auditEvents, which records the actor UPN, the operation, and the
         result. Intune audit retention is limited (roughly 30 days by default), so a policy
         older than that will have timestamps but no audit trail. The script says so rather
         than implying nothing happened.

    Also flags policies that exist but have no assignments, which is a common source of
    confusion: the policy is visible in the console, looks configured, and is reaching
    nothing.

    READ-ONLY. Every Graph call is a GET.

.PARAMETER TenantId
    Directory (tenant) ID of your Entra tenant.

.PARAMETER ClientId
    Application (client) ID of an app registration with DeviceManagementConfiguration.Read.All.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in CurrentUser\My or LocalMachine\My registered on the app.

.PARAMETER UseDeviceCode
    Sign in interactively with device code flow instead of a certificate.

.PARAMETER PolicyId
    Optional. Restrict the audit search to one policy ID. Without it, the script reports
    timestamps for every policy matching -NameMatch and audits each one.

.PARAMETER NameMatch
    Regex matched against policy names. Defaults to 'Hello'.

.PARAMETER MaxAuditPages
    Safety limit on how many pages of audit events to scan when a server-side filter is not
    accepted. Default 25 (about 25,000 events).

.EXAMPLE
    .\Get-IntunePolicyAuditHistory.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -CertificateThumbprint <thumbprint>

    Lists timestamps and assignment state for every matching policy, then audits each.

.EXAMPLE
    .\Get-IntunePolicyAuditHistory.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -UseDeviceCode -PolicyId <policy-guid>

    Audits one specific policy.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks

    Required permission : DeviceManagementConfiguration.Read.All
    Read-only. Exit codes: 0 = success, 1 = a query failed, 2 = authentication failed.
#>

[CmdletBinding(DefaultParameterSetName = 'Certificate')]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'Certificate')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [string]$PolicyId,

    [string]$NameMatch = 'Hello',

    [int]$MaxAuditPages = 25
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

function Get-GraphTokenByCertificate {
    param([string]$TenantId, [string]$ClientId, [string]$Thumbprint)

    $cert = Get-Item ("Cert:\CurrentUser\My\{0}" -f $Thumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item ("Cert:\LocalMachine\My\{0}" -f $Thumbprint) -ErrorAction SilentlyContinue }
    if (-not $cert) { throw ("Certificate {0} not found." -f $Thumbprint) }
    if (-not $cert.HasPrivateKey) { throw 'Certificate has no accessible private key.' }

    $b64u = {
        param([byte[]]$Bytes)
        [Convert]::ToBase64String($Bytes) -replace '\+', '-' -replace '/', '_' -replace '=', ''
    }
    $now = [DateTimeOffset]::UtcNow
    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $header  = @{ alg = 'RS256'; typ = 'JWT'; x5t = (& $b64u $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{
        aud = $aud; iss = $ClientId; sub = $ClientId
        jti = [Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(9).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $toSign = '{0}.{1}' -f (& $b64u ([Text.Encoding]::UTF8.GetBytes($header))),
                            (& $b64u ([Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign),
                         [Security.Cryptography.HashAlgorithmName]::SHA256,
                         [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $jwt = '{0}.{1}' -f $toSign, (& $b64u $sig)

    $resp = Invoke-RestMethod -Method POST -Uri $aud -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id             = $ClientId
        client_assertion      = $jwt
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        scope                 = 'https://graph.microsoft.com/.default'
        grant_type            = 'client_credentials'
    }
    return $resp.access_token
}

function Get-GraphTokenByDeviceCode {
    param([string]$TenantId, [string]$ClientId)

    $dc = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{ client_id = $ClientId; scope = 'https://graph.microsoft.com/.default offline_access' }

    Write-Host ''
    Write-Host $dc.message -ForegroundColor Yellow
    Write-Host ''

    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([int]$dc.interval)
        try {
            $tok = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{ grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                         client_id   = $ClientId
                         device_code = $dc.device_code }
            return $tok.access_token
        }
        catch {
            $body = ''
            try { $body = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch {}
            if ($body -notmatch 'authorization_pending') { throw }
        }
    }
    throw 'Device code sign-in timed out.'
}

# Token lifetime vs run length.
#
# Intune's audit endpoint throttles hard, and a full client-side scan can spend a long time
# asleep in Retry-After waits. A Graph access token is typically valid for about an hour, so
# a sufficiently throttled run outlives its own token and every subsequent call fails 401.
# Observed in practice: a scan that throttled repeatedly ran past the hour and died with
# "401 Unauthorized" partway through, which looks nothing like a token problem in the output.
#
# So the token is re-acquired on demand rather than captured once at startup, and a 401 is
# treated as "refresh and retry once" instead of a fatal error.
$script:TokenFactory = $null      # set in main, returns a fresh access token
$script:Headers      = $null

function Update-GraphToken {
    $script:Headers = @{ Authorization = ("Bearer " + (& $script:TokenFactory)) }
    return $script:Headers
}

function Invoke-GraphGet {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxRetry = 6)

    $refreshed = $false
    for ($attempt = 1; $attempt -le $MaxRetry; $attempt++) {
        try { return Invoke-RestMethod -Uri $Uri -Headers $script:Headers -Method GET }
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }

            if ($status -eq 401 -and -not $refreshed) {
                Write-Host '    token rejected (401) - refreshing and retrying' -ForegroundColor DarkYellow
                Update-GraphToken | Out-Null
                $refreshed = $true
                continue
            }
            if ($status -eq 429 -or $status -eq 503) {
                $wait = 10 * $attempt
                try { $ra = $_.Exception.Response.Headers['Retry-After']; if ($ra) { $wait = [int]$ra } } catch {}
                Write-Host ("    throttled ({0}), waiting {1}s (attempt {2}/{3})" -f $status, $wait, $attempt, $MaxRetry) -ForegroundColor DarkYellow
                Start-Sleep -Seconds $wait
                # A long sleep is exactly when the token ages out, so allow one more refresh.
                $refreshed = $false
                continue
            }
            throw
        }
    }
    throw ("Gave up after {0} attempts: {1}" -f $MaxRetry, $Uri)
}

function Get-GraphCollection {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxPages = 1000)
    $all = @(); $next = $Uri; $page = 0
    while ($next -and $page -lt $MaxPages) {
        $r = Invoke-GraphGet -Uri $next -Headers $Headers
        if ($r.value) { $all += $r.value }
        $next = $r.'@odata.nextLink'
        $page++
    }
    return $all
}

# Certificate auth can mint a fresh token silently, so the factory can be called again
# mid-run. Device code cannot - re-prompting the user halfway through a scan would be
# worse than failing - so that path returns the token acquired at sign-in.
if ($UseDeviceCode) {
    try { $deviceCodeToken = Get-GraphTokenByDeviceCode -TenantId $TenantId -ClientId $ClientId }
    catch {
        Write-Error ("Authentication failed: {0}" -f $_.Exception.Message)
        exit 2
    }
    $script:TokenFactory = { $deviceCodeToken }
}
else {
    $script:TokenFactory = {
        Get-GraphTokenByCertificate -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertificateThumbprint
    }
}

try { Update-GraphToken | Out-Null }
catch {
    Write-Error ("Authentication failed: {0}" -f $_.Exception.Message)
    exit 2
}
$headers = $script:Headers
$beta = 'https://graph.microsoft.com/beta'

# ------------------------------------------------------------------ 1. timestamps
Write-Host ''
Write-Host '=== 1. Policy timestamps and assignment state ===' -ForegroundColor Cyan

$targets = @()
try {
    $cps = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies?`$select=id,name,createdDateTime,lastModifiedDateTime" -f $beta) -Headers $headers
    foreach ($p in @($cps | Where-Object { $_.name -match $NameMatch })) {
        if ($PolicyId -and $p.id -ne $PolicyId) { continue }

        $asgCount = 0
        try {
            $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies/{1}/assignments" -f $beta, $p.id) -Headers $headers
            $asgCount = @($asg).Count
        }
        catch {}

        $targets += [pscustomobject]@{ Id = $p.id; Name = $p.name }

        Write-Host ''
        Write-Host ("  {0}" -f $p.name) -ForegroundColor Yellow
        Write-Host ("      id            : {0}" -f $p.id)
        Write-Host ("      created       : {0}" -f $p.createdDateTime)
        Write-Host ("      lastModified  : {0}" -f $p.lastModifiedDateTime)
        if ($asgCount -eq 0) {
            Write-Host       ("      assignments   : 0  <-- exists but targets nothing") -ForegroundColor Yellow
        }
        else {
            Write-Host ("      assignments   : {0}" -f $asgCount)
        }
    }
}
catch {
    $script:hadError = $true
    Write-Warning ("Could not list policies: {0}" -f $_.Exception.Message)
}

if ($PolicyId -and $targets.Count -eq 0) {
    $targets += [pscustomobject]@{ Id = $PolicyId; Name = '(specified by -PolicyId)' }
}

# ------------------------------------------------------------------ 2. audit
Write-Host ''
Write-Host '=== 2. Audit history ===' -ForegroundColor Cyan

$auditCache = $null
foreach ($t in $targets) {
    Write-Host ''
    Write-Host ("  --- {0}" -f $t.Name) -ForegroundColor Yellow

    $events = @()
    $serverFilterWorked = $false

    # Try the server-side filter first. It is much cheaper when the service accepts it.
    # Any failure here is reported, never swallowed - a silent failure on a "who changed
    # this?" question would be indistinguishable from "nobody changed it".
    Write-Host '      [1/2] trying server-side audit filter...'
    try {
        $filter = [uri]::EscapeDataString(("resources/any(r:r/resourceId eq '{0}')" -f $t.Id))
        $events = @(Get-GraphCollection -Uri ("{0}/deviceManagement/auditEvents?`$filter={1}" -f $beta, $filter) -Headers $headers)
        $serverFilterWorked = $true
        Write-Host ("      [1/2] server-side filter returned {0} event(s)" -f $events.Count)
    }
    catch {
        Write-Host ("      [1/2] server-side filter unavailable: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        $events = @()
    }

    # Fall back to scanning recent events client-side.
    if ($events.Count -eq 0) {
        if ($null -eq $auditCache) {
            Write-Host ("      [2/2] scanning up to {0} page(s) of recent audit events, this can take several minutes..." -f $MaxAuditPages)
            try {
                $auditCache = @(Get-GraphCollection -Uri ("{0}/deviceManagement/auditEvents?`$orderby=activityDateTime desc" -f $beta) -Headers $headers -MaxPages $MaxAuditPages)
                Write-Host ("      [2/2] retrieved {0} audit event(s) to scan" -f $auditCache.Count)
            }
            catch {
                $script:hadError = $true
                Write-Warning ("      [2/2] audit log not accessible: {0}" -f $_.Exception.Message)
                $auditCache = @()
            }
        }
        else {
            Write-Host ("      [2/2] reusing cached scan of {0} audit event(s)" -f $auditCache.Count)
        }
        $events = @($auditCache | Where-Object { $_.resources | Where-Object { $_.resourceId -eq $t.Id } })
        Write-Host ("      [2/2] {0} event(s) matched this policy id" -f $events.Count)
    }

    if ($events.Count -eq 0) {
        Write-Host '      RESULT: no audit events found for this policy.' -ForegroundColor Yellow
        if (-not $serverFilterWorked -and (-not $auditCache -or $auditCache.Count -eq 0)) {
            Write-Host '      WARNING: the audit log could not be read at all, so this is NOT evidence' -ForegroundColor Red
            Write-Host '      that nothing happened. Re-run when the tenant is not throttling.' -ForegroundColor Red
            $script:hadError = $true
        }
        else {
            Write-Host '      Intune audit retention is limited (about 30 days). If the policy is older'
            Write-Host '      than that, its creation event has aged out. Use the timestamps above.'
        }
        continue
    }

    Write-Host ("      RESULT: {0} audit event(s)" -f $events.Count) -ForegroundColor Green

    foreach ($e in ($events | Sort-Object activityDateTime)) {
        $actor = @($e.actor.userPrincipalName, $e.actor.applicationDisplayName, $e.actor.servicePrincipalName) |
                    Where-Object { $_ }
        Write-Host ''
        Write-Host ("      {0}  {1}" -f $e.activityDateTime, $e.displayName) -ForegroundColor Green
        Write-Host ("          operation : {0} / {1}" -f $e.activityType, $e.activityOperationType)
        Write-Host ("          result    : {0}" -f $e.activityResult)
        Write-Host ("          actor     : {0}" -f ($actor -join ' | '))
        if ($e.actor.userId) { Write-Host ("          userId    : {0}" -f $e.actor.userId) }
    }
}

Write-Host ''
Write-Host 'Done (read-only).' -ForegroundColor Green

if ($script:hadError) { exit 1 } else { exit 0 }
