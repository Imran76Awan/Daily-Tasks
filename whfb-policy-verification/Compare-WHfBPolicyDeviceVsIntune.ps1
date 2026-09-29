<#
.SYNOPSIS
    Compares the Windows Hello for Business policy Intune THINKS it sent against the values
    that actually landed in the registry on the device you run it from, and prints a
    match / mismatch / missing table.

.DESCRIPTION
    The Intune console reporting a policy as "Succeeded" only means the CSP accepted the
    request. It does not prove the values are present on the endpoint, and it will not tell
    you if Group Policy later overrode them.

    This script closes that loop. It runs on the device, reads the delivered WHfB values
    out of the registry, pulls the assigned WHfB policies from Microsoft Graph, normalises
    both sides to comparable values, then reports per setting:

        MATCH    - Intune value and registry value agree
        MISMATCH - both present but different (check for a GPO override)
        MISSING  - Intune has it, the device does not (delivery did not happen)
        EXTRA    - the device has it, no assigned Intune policy set it (GPO or a stale value)

    WHfB values are read from the tenant-scoped path, which is where WHfB actually writes:

        HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies

    AllowPINLogon is handled as a special case because it is a different CSP and is stored
    under PolicyManager, not under PassportForWork.

    READ-ONLY on both sides. Every Graph call is a GET, and nothing is written to the device.

.PARAMETER TenantId
    Directory (tenant) ID of your Entra tenant.

.PARAMETER ClientId
    Application (client) ID of an app registration with DeviceManagementConfiguration.Read.All.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in CurrentUser\My or LocalMachine\My registered on the app.
    Omit and use -UseDeviceCode to sign in interactively instead.

.PARAMETER UseDeviceCode
    Sign in interactively with device code flow rather than a certificate.

.PARAMETER NameMatch
    Regex matched against Intune policy names. Defaults to 'Hello'.

.PARAMETER CsvPath
    Optional path for a CSV of the comparison table.

.EXAMPLE
    .\Compare-WHfBPolicyDeviceVsIntune.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -CertificateThumbprint <thumbprint>

    Compares this device against the WHfB policies configured in Intune.

.EXAMPLE
    .\Compare-WHfBPolicyDeviceVsIntune.ps1 -TenantId <tenant-guid> -ClientId <app-guid> -UseDeviceCode -CsvPath .\whfb-compare.csv

    Interactive sign-in, results also written to CSV.

.NOTES
    Author : Imran Awan
    Blog   : https://endpointweekly.com/blog/windows-hello-for-business-policy-verify-device-registry-intune-graph.html
    Repo   : https://github.com/Imran76Awan/Daily-Tasks

    Required permission : DeviceManagementConfiguration.Read.All
    Read-only.
    Exit codes: 0 = everything matched, 1 = at least one MISMATCH or MISSING, 2 = auth or query failure.

    Caveat: the script compares against ALL policies matching -NameMatch, not only those
    assigned to this specific device. A setting reported MISSING may simply belong to a
    policy this device is not targeted by. Check the AssignedTo column before acting.
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

# ==================================================================== auth
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

function Invoke-GraphGet {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxRetry = 5)
    for ($attempt = 1; $attempt -le $MaxRetry; $attempt++) {
        try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET }
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 429 -or $status -eq 503) {
                $wait = 5 * $attempt
                try { $ra = $_.Exception.Response.Headers['Retry-After']; if ($ra) { $wait = [int]$ra } } catch {}
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
    $all = @(); $next = $Uri
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
    }
    catch { $script:groupCache[$GroupId] = ('<group {0}>' -f $GroupId) }
    return $script:groupCache[$GroupId]
}

function Format-Assignments {
    param($Assignments, [hashtable]$Headers)
    if (-not $Assignments -or $Assignments.Count -eq 0) { return 'NOT ASSIGNED' }
    $parts = @()
    foreach ($a in $Assignments) {
        $t = $a.target
        $kind = ($t.'@odata.type' -replace '#microsoft\.graph\.', '')
        if ($kind -eq 'allDevicesAssignmentTarget') { $parts += 'All devices'; continue }
        if ($kind -eq 'allLicensedUsersAssignmentTarget') { $parts += 'All users'; continue }
        if ($kind -eq 'exclusionGroupAssignmentTarget') { $parts += ('EXCLUDE:' + (Resolve-GroupName $t.groupId $Headers)); continue }
        if ($t.groupId) { $parts += (Resolve-GroupName $t.groupId $Headers) } else { $parts += $kind }
    }
    return ($parts -join '; ')
}

# ==================================================================== value normalisation
# Intune reports booleans as the text true/false, sometimes as an option suffix on the
# definition ID. The registry stores them as DWORD 1/0. Normalise both to 1/0 so they
# can be compared honestly rather than by string equality.
function ConvertTo-ComparableValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    switch -Regex ($s) {
        '^(?i)true$'    { return '1' }
        '^(?i)false$'   { return '0' }
        '^(?i)enabled$' { return '1' }
        '^(?i)disabled$' { return '0' }
        default         { return $s }
    }
}

# Reduce an Intune setting identifier to the registry value name it maps to.
# device_vendor_msft_passportforwork_{tenantid}_policies_pincomplexity_minimumpinlength
#   -> minimumpinlength
# ./Device/Vendor/MSFT/PassportForWork/<tenant>/Policies/DisablePostLogonProvisioning
#   -> disablepostlogonprovisioning
function Get-SettingLeafName {
    param([string]$Identifier)
    if (-not $Identifier) { return '' }
    if ($Identifier -match '/') { return (($Identifier -split '/')[-1]).ToLower() }
    return (($Identifier -split '_')[-1]).ToLower()
}

# ==================================================================== device side
Write-Host ''
Write-Host '=== Reading WHfB policy from this device ===' -ForegroundColor Cyan

$deviceValues = @{}   # lowercase value name -> @{ Name; Value; Path }

$whfbBase = 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork'
if (Test-Path $whfbBase) {
    foreach ($k in (@(Get-Item $whfbBase) + @(Get-ChildItem $whfbBase -Recurse -ErrorAction SilentlyContinue))) {
        $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($n in $item.GetValueNames()) {
            $deviceValues[$n.ToLower()] = @{
                Name  = $n
                Value = $item.GetValue($n)
                Path  = ($item.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Policies\\', '')
            }
        }
    }
}

# AllowPINLogon is a CredentialProviders CSP value, stored under PolicyManager rather than
# PassportForWork, and represented as <disabled/> rather than 0. Handle it explicitly.
$provRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
if (Test-Path $provRoot) {
    foreach ($k in (Get-ChildItem $provRoot -Recurse -ErrorAction SilentlyContinue)) {
        $item = Get-Item $k.PSPath -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($n in $item.GetValueNames()) {
            if ($n -eq 'AllowPINLogon') {
                $raw = [string]$item.GetValue($n)
                $normalised = if ($raw -match '(?i)disabled') { '0' } elseif ($raw -match '(?i)enabled') { '1' } else { $raw }
                $deviceValues['allowpinlogon'] = @{
                    Name  = 'AllowPINLogon'
                    Value = $normalised
                    Path  = 'PolicyManager\providers\<EnrollmentId>\default\Device\CredentialProviders'
                }
            }
        }
    }
}

Write-Host ("  Found {0} WHfB-related value(s) on this device." -f $deviceValues.Count)

# ==================================================================== intune side
Write-Host ''
Write-Host '=== Reading WHfB policy from Intune ===' -ForegroundColor Cyan

try {
    if ($UseDeviceCode) { $token = Get-GraphTokenByDeviceCode -TenantId $TenantId -ClientId $ClientId }
    else { $token = Get-GraphTokenByCertificate -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertificateThumbprint }
}
catch {
    Write-Error ("Authentication failed: {0}" -f $_.Exception.Message)
    exit 2
}
$headers = @{ Authorization = "Bearer $token" }
$beta = 'https://graph.microsoft.com/beta'

$intuneSettings = @{}   # leaf name -> @{ Setting; Value; Policy; AssignedTo }

function Add-IntuneSetting {
    param([string]$Identifier, $Value, [string]$Policy, [string]$AssignedTo)
    $leaf = Get-SettingLeafName -Identifier $Identifier
    if (-not $leaf) { return }
    $intuneSettings[$leaf] = @{
        Setting    = $Identifier
        Value      = (ConvertTo-ComparableValue $Value)
        RawValue   = $Value
        Policy     = $Policy
        AssignedTo = $AssignedTo
    }
}

function Read-SettingInstance {
    param($Instance, [string]$Policy, [string]$AssignedTo)
    if (-not $Instance) { return }
    $defId = $Instance.settingDefinitionId
    $type  = $Instance.'@odata.type'

    switch -Wildcard ($type) {
        '*ChoiceSettingInstance' {
            $raw = $Instance.choiceSettingValue.value
            $val = $raw -replace [regex]::Escape($defId + '_'), ''
            Add-IntuneSetting -Identifier $defId -Value $val -Policy $Policy -AssignedTo $AssignedTo
            foreach ($c in $Instance.choiceSettingValue.children) { Read-SettingInstance -Instance $c -Policy $Policy -AssignedTo $AssignedTo }
        }
        '*SimpleSettingInstance' {
            Add-IntuneSetting -Identifier $defId -Value $Instance.simpleSettingValue.value -Policy $Policy -AssignedTo $AssignedTo
        }
        '*SimpleSettingCollectionInstance' {
            $val = (($Instance.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join ', ')
            Add-IntuneSetting -Identifier $defId -Value $val -Policy $Policy -AssignedTo $AssignedTo
        }
        '*GroupSettingCollectionInstance' {
            foreach ($g in $Instance.groupSettingCollectionValue) {
                foreach ($c in $g.children) { Read-SettingInstance -Instance $c -Policy $Policy -AssignedTo $AssignedTo }
            }
        }
        '*GroupSettingInstance' {
            foreach ($c in $Instance.groupSettingValue.children) { Read-SettingInstance -Instance $c -Policy $Policy -AssignedTo $AssignedTo }
        }
    }
}

try {
    $cps = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies?`$select=id,name" -f $beta) -Headers $headers
    foreach ($p in @($cps | Where-Object { $_.name -match $NameMatch })) {
        $asg = @()
        try { $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies/{1}/assignments" -f $beta, $p.id) -Headers $headers } catch {}
        $asgText  = Format-Assignments -Assignments $asg -Headers $headers
        $settings = Get-GraphCollection -Uri ("{0}/deviceManagement/configurationPolicies/{1}/settings" -f $beta, $p.id) -Headers $headers
        foreach ($s in $settings) { Read-SettingInstance -Instance $s.settingInstance -Policy $p.name -AssignedTo $asgText }
    }
}
catch {
    $script:hadError = $true
    Write-Warning ("Settings Catalog query failed: {0}" -f $_.Exception.Message)
}

try {
    $dcs = Get-GraphCollection -Uri ("{0}/deviceManagement/deviceConfigurations?`$select=id,displayName" -f $beta) -Headers $headers
    foreach ($d in @($dcs | Where-Object { $_.displayName -match $NameMatch })) {
        $full = Invoke-GraphGet -Uri ("{0}/deviceManagement/deviceConfigurations/{1}" -f $beta, $d.id) -Headers $headers
        $asg = @()
        try { $asg = Get-GraphCollection -Uri ("{0}/deviceManagement/deviceConfigurations/{1}/assignments" -f $beta, $d.id) -Headers $headers } catch {}
        $asgText = Format-Assignments -Assignments $asg -Headers $headers
        foreach ($o in $full.omaSettings) {
            Add-IntuneSetting -Identifier $o.omaUri -Value $o.value -Policy $d.displayName -AssignedTo $asgText
        }
    }
}
catch {
    $script:hadError = $true
    Write-Warning ("deviceConfigurations query failed: {0}" -f $_.Exception.Message)
}

Write-Host ("  Found {0} WHfB setting(s) configured in Intune." -f $intuneSettings.Count)

# ==================================================================== compare
$results = [System.Collections.Generic.List[object]]::new()

foreach ($leaf in ($intuneSettings.Keys | Sort-Object)) {
    $i = $intuneSettings[$leaf]
    if ($deviceValues.ContainsKey($leaf)) {
        $devRaw  = $deviceValues[$leaf].Value
        $devNorm = ConvertTo-ComparableValue $devRaw
        $status  = if ($devNorm -eq $i.Value) { 'MATCH' } else { 'MISMATCH' }
        $results.Add([pscustomobject]@{
            Setting     = $deviceValues[$leaf].Name
            Status      = $status
            IntuneValue = $i.RawValue
            DeviceValue = $devRaw
            Policy      = $i.Policy
            AssignedTo  = $i.AssignedTo
            RegistryPath = $deviceValues[$leaf].Path
        })
    }
    else {
        $results.Add([pscustomobject]@{
            Setting     = (Get-SettingLeafName $i.Setting)
            Status      = 'MISSING'
            IntuneValue = $i.RawValue
            DeviceValue = '(absent)'
            Policy      = $i.Policy
            AssignedTo  = $i.AssignedTo
            RegistryPath = '(not found)'
        })
    }
}

foreach ($leaf in ($deviceValues.Keys | Sort-Object)) {
    if (-not $intuneSettings.ContainsKey($leaf)) {
        $results.Add([pscustomobject]@{
            Setting     = $deviceValues[$leaf].Name
            Status      = 'EXTRA'
            IntuneValue = '(not configured)'
            DeviceValue = $deviceValues[$leaf].Value
            Policy      = '(none matched)'
            AssignedTo  = ''
            RegistryPath = $deviceValues[$leaf].Path
        })
    }
}

Write-Host ''
Write-Host '=== Comparison ===' -ForegroundColor Cyan
Write-Host ''
$fmt = "{0,-40} {1,-10} {2,-16} {3,-16}"
Write-Host ($fmt -f 'SETTING', 'STATUS', 'INTUNE', 'DEVICE')
Write-Host ('-' * 88)
foreach ($r in ($results | Sort-Object Status, Setting)) {
    $colour = switch ($r.Status) {
        'MATCH'    { 'Green' }
        'MISMATCH' { 'Red' }
        'MISSING'  { 'Red' }
        'EXTRA'    { 'Yellow' }
        default    { 'Gray' }
    }
    Write-Host ($fmt -f $r.Setting, $r.Status, $r.IntuneValue, $r.DeviceValue) -ForegroundColor $colour
}

$match    = @($results | Where-Object { $_.Status -eq 'MATCH' }).Count
$mismatch = @($results | Where-Object { $_.Status -eq 'MISMATCH' }).Count
$missing  = @($results | Where-Object { $_.Status -eq 'MISSING' }).Count
$extra    = @($results | Where-Object { $_.Status -eq 'EXTRA' }).Count

Write-Host ''
Write-Host ("  MATCH {0}   MISMATCH {1}   MISSING {2}   EXTRA {3}" -f $match, $mismatch, $missing, $extra)

if ($mismatch -gt 0) {
    Write-Host ''
    Write-Host '  A MISMATCH usually means Group Policy is overriding Intune for that setting.' -ForegroundColor Yellow
    Write-Host '  Check HKLM\SOFTWARE\Policies\Microsoft\PassportForWork for a competing value.' -ForegroundColor Yellow
}
if ($missing -gt 0) {
    Write-Host ''
    Write-Host '  A MISSING setting may simply belong to a policy this device is not assigned.' -ForegroundColor Yellow
    Write-Host '  Check the AssignedTo column in the CSV or full object output before acting.' -ForegroundColor Yellow
}

if ($CsvPath) {
    try {
        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host ("  CSV written: {0}" -f $CsvPath) -ForegroundColor Green
    }
    catch {
        $script:hadError = $true
        Write-Warning ("Could not write CSV: {0}" -f $_.Exception.Message)
    }
}

Write-Host ''
Write-Host 'Done (read-only).' -ForegroundColor Green

if ($script:hadError) { exit 2 }
if ($mismatch -gt 0 -or $missing -gt 0) { exit 1 }
exit 0
