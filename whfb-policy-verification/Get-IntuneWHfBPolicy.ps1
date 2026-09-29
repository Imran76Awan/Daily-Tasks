<#
.SYNOPSIS
    Reports every Windows Hello for Business policy configured in Intune, across all three
    policy surfaces, with the real setting values and the groups each policy is assigned to.

.DESCRIPTION
    WHfB policy does not live in one place in Intune. Depending on how it was created it can
    sit in any of three separate Graph collections:

      1. deviceManagement/configurationPolicies   - Settings Catalog policies
      2. deviceManagement/deviceConfigurations    - legacy templates and custom OMA-URI
      3. deviceManagement/intents                 - endpoint security (Account Protection)

    A script that queries only configurationPolicies will silently miss custom OMA-URI
    policies, which is exactly how a delivered setting ends up looking "not configured".

    This script queries all three, expands the deeply nested Settings Catalog structure so
    you see real values rather than parent definition IDs, resolves assignment group names,
    and prints everything as a flat readable list.

    READ-ONLY. Every Graph call is a GET. Nothing in the tenant is created or changed.

.PARAMETER TenantId
    Directory (tenant) ID of your Entra tenant.

.PARAMETER ClientId
    Application (client) ID of an app registration with DeviceManagementConfiguration.Read.All
    granted as an application permission and admin-consented.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in CurrentUser\My or LocalMachine\My whose public key is
    registered on the app. Omit this and pass -UseDeviceCode to sign in interactively instead.

.PARAMETER UseDeviceCode
    Use device code sign-in instead of certificate auth. The signed-in account needs read
    access to Intune configuration.

.PARAMETER NameMatch
    Regex matched against policy names. Defaults to 'Hello' so it picks up WHfB policies
    whatever your naming convention. Use '.' to list everything.

.PARAMETER CsvPath
    Optional. Writes a flat CSV of PolicyName, Surface, Setting, Value, AssignedTo.

.EXAMPLE
    .\Get-IntuneWHfBPolicy.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -CertificateThumbprint <thumbprint>

    Lists every WHfB policy with its expanded settings and assignments.

.EXAMPLE
    .\Get-IntuneWHfBPolicy.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -UseDeviceCode -CsvPath .\whfb-policy.csv

    Signs in interactively and exports the result to CSV.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks

    Required permission : DeviceManagementConfiguration.Read.All (Application or Delegated)
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

    [string]$NameMatch = 'Hello',

    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false
$rows = [System.Collections.Generic.List[object]]::new()

# ------------------------------------------------------------------ auth
function Get-GraphTokenByCertificate {
    param([string]$TenantId, [string]$ClientId, [string]$Thumbprint)

    $cert = Get-Item ("Cert:\CurrentUser\My\{0}" -f $Thumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item ("Cert:\LocalMachine\My\{0}" -f $Thumbprint) -ErrorAction SilentlyContinue }
    if (-not $cert) { throw ("Certificate {0} not found in CurrentUser\My or LocalMachine\My" -f $Thumbprint) }
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
                -Body @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                         client_id  = $ClientId
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

# ------------------------------------------------------------------ graph helpers
function Invoke-GraphGet {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxRetry = 5)

    for ($attempt = 1; $attempt -le $MaxRetry; $attempt++) {
        try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET }
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 429 -or $status -eq 503) {
                $wait = 5 * $attempt
                try {
                    $ra = $_.Exception.Response.Headers['Retry-After']
                    if ($ra) { $wait = [int]$ra }
                } catch {}
                Write-Verbose ("Throttled ({0}). Waiting {1}s." -f $status, $wait)
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
    throw ("Gave up after {0} throttled attempts: {1}" -f $MaxRetry, $Uri)
}

function Get-GraphCollection {
    param([string]$Uri, [hashtable]$Headers)
    $all = @()
    $next = $Uri
    while ($next) {
        $r = Invoke-GraphGet -Uri $next -Headers $Headers
        if ($r.value) { $all += $r.value }
        $next = $r.'@odata.nextLink'
    }
    return $all
}

$script:groupCache = @{}
function Resolve-GroupName {
    param([string]$GroupId, [hashtable]$Headers)
    if (-not $GroupId) { return '' }
    if ($script:groupCache.ContainsKey($GroupId)) { return $script:groupCache[$GroupId] }
    try {
        $g = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/groups/{0}?`$select=displayName" -f $GroupId) -Headers $Headers
        $script:groupCache[$GroupId] = $g.displayName
        return $g.displayName
    }
    catch {
        $script:groupCache[$GroupId] = ('<group {0}>' -f $GroupId)
        return $script:groupCache[$GroupId]
    }
}

function Format-Assignments {
    param($Assignments, [hashtable]$Headers)
    if (-not $Assignments -or $Assignments.Count -eq 0) { return 'NOT ASSIGNED' }
    $parts = @()
    foreach ($a in $Assignments) {
        $t    = $a.target
        $kind = ($t.'@odata.type' -replace '#microsoft\.graph\.', '')
        switch ($kind) {
            'allDevicesAssignmentTarget'  { $parts += 'All devices' }
            'allLicensedUsersAssignmentTarget' { $parts += 'All users' }
            'exclusionGroupAssignmentTarget'   { $parts += ('EXCLUDE: {0}' -f (Resolve-GroupName $t.groupId $Headers)) }
            default {
                if ($t.groupId) { $parts += (Resolve-GroupName $t.groupId $Headers) }
                else { $parts += $kind }
            }
        }
    }
    return ($parts -join '; ')
}

# ------------------------------------------------------------------ settings catalog expansion
# Settings Catalog returns a nested tree. The useful values sit inside
# groupSettingCollectionValue -> children, sometimes several levels deep. Walking it is the
# only way to get real values instead of parent definition IDs.
function Expand-SettingInstance {
    param($Instance, [int]$Depth = 0, [string]$PolicyName, [string]$Surface, [string]$AssignedTo)

    if (-not $Instance) { return }
    $defId = $Instance.settingDefinitionId
    $type  = $Instance.'@odata.type'
    $short = $defId -replace '^device_vendor_msft_', '' -replace '^user_vendor_msft_', 'USER:'
    $pad   = ' ' * (4 + $Depth * 2)

    switch -Wildcard ($type) {
        '*ChoiceSettingInstance' {
            $raw = $Instance.choiceSettingValue.value
            # The chosen option is the definition ID with an option suffix. Strip the prefix
            # so "..._usebiometrics_true" reads as "true".
            $val = $raw -replace [regex]::Escape($defId + '_'), ''
            Write-Host ("{0}{1,-58} = {2}" -f $pad, $short, $val)
            $rows.Add([pscustomobject]@{ PolicyName = $PolicyName; Surface = $Surface; Setting = $short; Value = $val; AssignedTo = $AssignedTo })
            foreach ($c in $Instance.choiceSettingValue.children) {
                Expand-SettingInstance -Instance $c -Depth ($Depth + 1) -PolicyName $PolicyName -Surface $Surface -AssignedTo $AssignedTo
            }
        }
        '*SimpleSettingInstance' {
            $val = $Instance.simpleSettingValue.value
            Write-Host ("{0}{1,-58} = {2}" -f $pad, $short, $val)
            $rows.Add([pscustomobject]@{ PolicyName = $PolicyName; Surface = $Surface; Setting = $short; Value = $val; AssignedTo = $AssignedTo })
        }
        '*SimpleSettingCollectionInstance' {
            $val = (($Instance.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join ', ')
            Write-Host ("{0}{1,-58} = {2}" -f $pad, $short, $val)
            $rows.Add([pscustomobject]@{ PolicyName = $PolicyName; Surface = $Surface; Setting = $short; Value = $val; AssignedTo = $AssignedTo })
        }
        '*GroupSettingCollectionInstance' {
            Write-Host ("{0}[group] {1}" -f $pad, $short) -ForegroundColor DarkCyan
            foreach ($g in $Instance.groupSettingCollectionValue) {
                foreach ($c in $g.children) {
                    Expand-SettingInstance -Instance $c -Depth ($Depth + 1) -PolicyName $PolicyName -Surface $Surface -AssignedTo $AssignedTo
                }
            }
        }
        '*GroupSettingInstance' {
            Write-Host ("{0}[group] {1}" -f $pad, $short) -ForegroundColor DarkCyan
            foreach ($c in $Instance.groupSettingValue.children) {
                Expand-SettingInstance -Instance $c -Depth ($Depth + 1) -PolicyName $PolicyName -Surface $Surface -AssignedTo $AssignedTo
            }
        }
        default {
            Write-Host ("{0}(unhandled type {1}) {2}" -f $pad, $type, $short) -ForegroundColor DarkYellow
        }
    }
}

# ------------------------------------------------------------------ main
try {
    if ($UseDeviceCode) { $token = Get-GraphTokenByDeviceCode -TenantId $TenantId -ClientId $ClientId }
    else { $token = Get-GraphTokenByCertificate -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertificateThumbprint }
}
catch {
    Write-Error ("Authentication failed: {0}" -f $_.Exception.Message)
    exit 2
}
$headers = @{ Authorization = "Bearer $token" }
$beta    = 'https://graph.microsoft.com/beta'

Write-Host ''
Write-Host '=== 1. Settings Catalog (configurationPolicies) ===' -ForegroundColor Cyan
try {
    $cps = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies?`$select=id,name,platforms,technologies,createdDateTime,lastModifiedDateTime" -f $beta) -Headers $headers
    $hit = @($cps | Where-Object { $_.name -match $NameMatch })
    Write-Host ("Matched {0} of {1} policies" -f $hit.Count, $cps.Count)

    foreach ($p in $hit) {
        $asg  = @()
        try { $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies/{1}/assignments" -f $beta, $p.id) -Headers $headers } catch {}
        $asgText = Format-Assignments -Assignments $asg -Headers $headers

        Write-Host ''
        Write-Host ("--- {0}" -f $p.name) -ForegroundColor Yellow
        Write-Host ("    id           : {0}" -f $p.id)
        Write-Host ("    created      : {0}" -f $p.createdDateTime)
        Write-Host ("    lastModified : {0}" -f $p.lastModifiedDateTime)
        Write-Host ("    assigned to  : {0}" -f $asgText)

        $settings = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies/{1}/settings" -f $beta, $p.id) -Headers $headers
        foreach ($s in $settings) {
            Expand-SettingInstance -Instance $s.settingInstance -PolicyName $p.name -Surface 'SettingsCatalog' -AssignedTo $asgText
        }
    }
}
catch {
    $script:hadError = $true
    Write-Warning ("configurationPolicies query failed: {0}" -f $_.Exception.Message)
}

Write-Host ''
Write-Host '=== 2. Legacy templates and custom OMA-URI (deviceConfigurations) ===' -ForegroundColor Cyan
try {
    $dcs = Get-GraphCollection -Uri ("{0}/deviceManagement/deviceConfigurations?`$select=id,displayName" -f $beta) -Headers $headers
    $hit = @($dcs | Where-Object { $_.displayName -match $NameMatch })
    Write-Host ("Matched {0} of {1} profiles" -f $hit.Count, $dcs.Count)

    foreach ($d in $hit) {
        $full = Invoke-GraphGet -Uri ("{0}/deviceManagement/deviceConfigurations/{1}" -f $beta, $d.id) -Headers $headers
        $asg  = @()
        try { $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/deviceConfigurations/{1}/assignments" -f $beta, $d.id) -Headers $headers } catch {}
        $asgText = Format-Assignments -Assignments $asg -Headers $headers

        Write-Host ''
        Write-Host ("--- {0}" -f $d.displayName) -ForegroundColor Yellow
        Write-Host ("    type        : {0}" -f ($full.'@odata.type' -replace '#microsoft\.graph\.', ''))
        Write-Host ("    assigned to : {0}" -f $asgText)

        if ($full.omaSettings) {
            foreach ($o in $full.omaSettings) {
                Write-Host ("    OMA setting : {0}" -f $o.displayName)
                Write-Host ("      OMA-URI   : {0}" -f $o.omaUri)
                Write-Host ("      Type      : {0}" -f ($o.'@odata.type' -replace '#microsoft\.graph\.omaSetting', ''))
                Write-Host ("      Value     : {0}" -f $o.value)
                $rows.Add([pscustomobject]@{ PolicyName = $d.displayName; Surface = 'CustomOMAURI'; Setting = $o.omaUri; Value = $o.value; AssignedTo = $asgText })
            }
        }
        else {
            foreach ($prop in $full.PSObject.Properties) {
                if ($prop.Name -in @('id','displayName','description','createdDateTime','lastModifiedDateTime','version','roleScopeTagIds','supportsScopeTags','@odata.type','@odata.context')) { continue }
                if ($null -eq $prop.Value) { continue }
                Write-Host ("      {0,-48} = {1}" -f $prop.Name, $prop.Value)
                $rows.Add([pscustomobject]@{ PolicyName = $d.displayName; Surface = 'LegacyTemplate'; Setting = $prop.Name; Value = $prop.Value; AssignedTo = $asgText })
            }
        }
    }
}
catch {
    $script:hadError = $true
    Write-Warning ("deviceConfigurations query failed: {0}" -f $_.Exception.Message)
}

Write-Host ''
Write-Host '=== 3. Endpoint security (intents) ===' -ForegroundColor Cyan
try {
    $intents = Get-GraphCollection -Uri ("{0}/deviceManagement/intents?`$select=id,displayName,templateId" -f $beta) -Headers $headers
    $hit = @($intents | Where-Object { $_.displayName -match $NameMatch })
    Write-Host ("Matched {0} of {1} intents" -f $hit.Count, $intents.Count)

    foreach ($i in $hit) {
        $asg = @()
        try { $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/intents/{1}/assignments" -f $beta, $i.id) -Headers $headers } catch {}
        $asgText = Format-Assignments -Assignments $asg -Headers $headers

        Write-Host ''
        Write-Host ("--- {0}" -f $i.displayName) -ForegroundColor Yellow
        Write-Host ("    assigned to : {0}" -f $asgText)

        $st = Get-GraphCollection -Uri ("{0}/deviceManagement/intents/{1}/settings" -f $beta, $i.id) -Headers $headers
        foreach ($s in $st) {
            $name = $s.definitionId -replace '^deviceConfiguration--', ''
            Write-Host ("      {0,-48} = {1}" -f $name, $s.value)
            $rows.Add([pscustomobject]@{ PolicyName = $i.displayName; Surface = 'EndpointSecurity'; Setting = $name; Value = $s.value; AssignedTo = $asgText })
        }
    }
}
catch {
    Write-Warning ("intents query failed or not permitted: {0}" -f $_.Exception.Message)
}

if ($CsvPath) {
    try {
        $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host ("CSV written: {0}" -f $CsvPath) -ForegroundColor Green
    }
    catch {
        $script:hadError = $true
        Write-Warning ("Could not write CSV: {0}" -f $_.Exception.Message)
    }
}

Write-Host ''
Write-Host ("Done (read-only). {0} setting rows collected." -f $rows.Count) -ForegroundColor Green

if ($script:hadError) { exit 1 } else { exit 0 }
