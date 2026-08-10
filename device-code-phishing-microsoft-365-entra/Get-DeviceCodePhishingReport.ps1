<#
.SYNOPSIS
    Queries Entra ID sign-in logs for device code flow events, correlates with Intune, and exports
    both a CSV and a professional HTML investigation report.

.DESCRIPTION
    Uses Microsoft Graph to retrieve all sign-in events where AuthenticationProtocol = deviceCode
    over a configurable lookback window. For each hit it attempts to correlate the signing device
    with an Intune managed device record using the Azure AD Device ID from the sign-in log.

    By default runs against the whole tenant. Use -GroupId or -GroupName to scope the report
    to members of a specific Entra ID group (e.g. a department, a pilot ring, or an exec group).

    Exports two files to the desktop (or -ExportPath):
      1. DeviceCodePhishingReport_YYYYMMDD_HHmmss.csv  — raw data, import into Excel or SIEM
      2. DeviceCodePhishingReport_YYYYMMDD_HHmmss.html — colour-coded HTML report with risk
         classification, search, filter, and sortable table — open in any browser

    Risk levels assigned automatically:
      HIGH   — app is not a known Microsoft admin/dev tool (unknown third-party or suspicious name)
      MEDIUM — service/room accounts (bcgcloud.onmicrosoft.com or similar tenant service domains)
      LOW    — known Microsoft tools: Azure CLI, Graph CLI, Az PowerShell, SharePoint Shell, Dev Tunnels

    Run this against a tenant or group to answer: which users and devices were targeted or compromised?

.PARAMETER LookbackDays
    Days of sign-in history to query. Default: 30.
    Note: Entra ID retains sign-in logs for 30 days (P1/P2) or 7 days (free tier).

.PARAMETER GroupId
    Object ID of an Entra ID group. Scopes report to members of this group.

.PARAMETER GroupName
    Display name of an Entra ID group. Resolved to an Object ID automatically.

.PARAMETER ExportPath
    Base path for output files (without extension). Defaults to Desktop with a date-stamped name.
    The script appends .csv and .html automatically.

.PARAMETER TenantId
    Entra ID tenant ID. Required for certificate auth.

.PARAMETER ClientId
    App registration client ID. Required for certificate auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate in the local cert store. Required for certificate auth.

.PARAMETER SuccessfulOnly
    Export only successful sign-ins (ErrorCode = 0).

.PARAMETER NoHtml
    Skip HTML report generation — export CSV only.

.PARAMETER ServiceAccountDomains
    Additional UPN domain suffixes to treat as service/room accounts (MEDIUM risk).
    Default includes *.onmicrosoft.com non-primary domains. Example: @('myrooms.contoso.com')

.NOTES
    Requires: Microsoft.Graph.Authentication only (all Graph calls via Invoke-MgGraphRequest)
    Scopes:   AuditLog.Read.All, DeviceManagementManagedDevices.Read.All, GroupMember.Read.All
    Blog:     https://endpointweekly.com/blog/device-code-phishing-microsoft-365-entra.html
    GitHub:   https://github.com/Imran76Awan/Daily-Tasks/tree/main/device-code-phishing-microsoft-365-entra

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD"
    Cert auth, last 30 days, whole tenant. Generates both CSV and HTML on the desktop.

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -GroupName "Finance" -LookbackDays 30
    Interactive device code sign-in, scoped to the Finance group.

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "xxxxxxxx" -CertificateThumbprint "AABB..." -SuccessfulOnly -NoHtml
    Cert auth, successful sign-ins only, CSV export only.
#>

[CmdletBinding()]
param(
    [int]$LookbackDays = 30,
    [string]$GroupId,
    [string]$GroupName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$ExportPath,
    [switch]$SuccessfulOnly,
    [switch]$NoHtml,
    [string[]]$ServiceAccountDomains = @()
)

#region --- Prerequisites ---

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}

#endregion

#region --- Risk classification ---

# Well-known Microsoft admin and developer tool app IDs that legitimately use device code flow.
# Add your own approved internal app IDs to this list.
$KnownSafeAppIds = @(
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46'  # Microsoft Azure CLI
    '14d82eec-204b-4c2f-b7e8-296a70dab67e'  # Microsoft Graph Command Line Tools
    '1950a258-227b-4e31-a9cf-717495945fc2'  # Microsoft Azure PowerShell
    '9bc3ab49-b65d-410a-85ad-de819febfddc'  # Microsoft SharePoint Online Management Shell
    'c0df98ca-23b4-4bce-bb9f-72039b28d3a5'  # Dev Tunnels
    '29d9ed98-a469-4536-ade2-f981bc1d605e'  # Microsoft Authentication Broker
    '04f0c124-f2bc-4f59-8241-bf6df9866bbd'  # Microsoft Office
    'd3590ed6-52b3-4102-aeff-aad2292ab01c'  # Microsoft Office (desktop)
    '0ec893e0-5785-4de6-99da-4ed124e5296c'  # Office UWP PWA
    'bc59ab01-8403-45c6-8796-ac3ef710b3e3'  # Outlook Mobile
    '27922004-5251-4030-b22d-91ecd9a37ea4'  # Outlook iOS
)

function Get-SignInRisk {
    param(
        [string]$AppId,
        [string]$AppName,
        [string]$Upn,
        [string[]]$ServiceDomains
    )

    # Service/room accounts: non-primary onmicrosoft.com tenant domains or custom service domains
    $allServiceDomains = @('bcgcloud.onmicrosoft.com') + $ServiceDomains
    foreach ($d in $allServiceDomains) {
        if ($Upn -like "*@$d") { return 'medium' }
    }
    # Generic pattern: onmicrosoft.com accounts that are not the primary tenant (e.g. contoso.onmicrosoft.com)
    # Primary tenant UPNs typically end in @{tenant}.onmicrosoft.com but have human-style names.
    # Room/service accounts often have numeric or code-style local parts.
    if ($Upn -match '@[^@]+\.onmicrosoft\.com$' -and $Upn -match '^[a-z]{2,4}\.\d+\.\d+@') {
        return 'medium'
    }

    # Known safe Microsoft tool
    if ($KnownSafeAppIds -contains $AppId) { return 'low' }

    # App name contains "Example" - default name for new/test app registrations
    if ($AppName -match '\bExample\b') { return 'high' }

    # Unknown app not in the safe list - needs verification
    return 'high'
}

#endregion

#region --- Connect ---

Write-Host ""
Write-Host "Device Code Phishing  -  Tenant Investigation Script" -ForegroundColor Cyan
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Gray

if ($TenantId -and $ClientId -and $CertificateThumbprint) {
    Write-Host "Authenticating with certificate..." -ForegroundColor Gray
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
}
else {
    Write-Host "No certificate parameters supplied - using device code (browser-independent)..." -ForegroundColor Gray
    $scopes = @("AuditLog.Read.All", "DeviceManagementManagedDevices.Read.All")
    if ($GroupId -or $GroupName) { $scopes += "GroupMember.Read.All" }
    Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome -ErrorAction Stop
}

#endregion

#region --- Resolve group and load member UPNs (if scoped) ---

$groupMemberUPNs = $null

if ($GroupId -or $GroupName) {

    if (-not $GroupId) {
        Write-Host "Resolving group name '$GroupName'..." -ForegroundColor Gray
        $encodedName = [Uri]::EscapeDataString("displayName eq '$GroupName'")
        $groupResp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$encodedName&`$select=id,displayName" -Method GET -ErrorAction Stop
        $group = $groupResp.value | Select-Object -First 1
        if (-not $group) {
            Write-Warning "Group '$GroupName' not found. Check the display name and try again."
            return
        }
        $GroupId = $group.id
        Write-Host "Resolved to Group ID: $GroupId" -ForegroundColor Gray
    }

    Write-Host "Loading group members..." -ForegroundColor Gray
    try {
        $groupMemberUPNs = @{}
        $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=userPrincipalName&`$top=999"
        do {
            $membersResp = Invoke-MgGraphRequest -Uri $membersUri -Method GET -ErrorAction Stop
            foreach ($m in $membersResp.value) {
                if ($m.userPrincipalName) {
                    $groupMemberUPNs[$m.userPrincipalName.ToLower()] = $true
                }
            }
            $membersUri = $membersResp.'@odata.nextLink'
        } while ($membersUri)
        Write-Host "Group contains $($groupMemberUPNs.Count) user(s)." -ForegroundColor Gray
    }
    catch {
        Write-Warning "Failed to load group members: $($_.Exception.Message)"
        return
    }
}

#endregion

#region --- Query sign-in logs ---

$cutoff = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$filter = "authenticationProtocol eq 'deviceCode' and createdDateTime ge $cutoff"
if ($SuccessfulOnly) {
    $filter += " and status/errorCode eq 0"
}

Write-Host "Querying sign-in logs  -  last $LookbackDays days, filter: deviceCode..." -ForegroundColor Gray

$select = "id,createdDateTime,userPrincipalName,userDisplayName,ipAddress,location,appDisplayName,appId,deviceDetail,status,riskLevelDuringSignIn,riskLevelAggregated,conditionalAccessStatus,clientAppUsed,authenticationProtocol"
$encodedFilter = [Uri]::EscapeDataString($filter)
$uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$select=$select&`$top=999"

$signIns = [System.Collections.Generic.List[object]]::new()

try {
    do {
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        foreach ($item in $response.value) { $signIns.Add($item) }
        $uri = $response.'@odata.nextLink'
    } while ($uri)
}
catch {
    Write-Warning "Query failed: $($_.Exception.Message)"
    Write-Host "Ensure the app registration has AuditLog.Read.All application permission." -ForegroundColor Yellow
    return
}

Write-Host "Found $($signIns.Count) device code sign-in event(s) across the tenant." -ForegroundColor $(if ($signIns.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($groupMemberUPNs -ne $null) {
    $signIns = $signIns | Where-Object { $groupMemberUPNs.ContainsKey($_.userPrincipalName.ToLower()) }
    Write-Host "After filtering to group members: $($signIns.Count) event(s)." -ForegroundColor $(if ($signIns.Count -gt 0) { 'Yellow' } else { 'Green' })
}

if ($signIns.Count -eq 0) {
    Write-Host "No device code sign-ins found. Scope appears clean for this window." -ForegroundColor Green
    return
}

#endregion

#region --- Correlate with Intune ---

Write-Host "Correlating with Intune managed device records..." -ForegroundColor Gray

$intuneCache = @{}

$results = foreach ($signIn in $signIns) {

    $deviceId = $signIn.deviceDetail.deviceId
    $intuneDevice = $null

    if ($deviceId -and $deviceId -ne "00000000-0000-0000-0000-000000000000") {
        if (-not $intuneCache.ContainsKey($deviceId)) {
            try {
                $encodedDeviceFilter = [Uri]::EscapeDataString("azureADDeviceId eq '$deviceId'")
                $intuneResp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$encodedDeviceFilter&`$select=deviceName,operatingSystem,osVersion,lastSyncDateTime,complianceState,managementState&`$top=1" -Method GET -ErrorAction SilentlyContinue
                $intuneCache[$deviceId] = $intuneResp.value | Select-Object -First 1
            }
            catch {
                $intuneCache[$deviceId] = $null
            }
        }
        $intuneDevice = $intuneCache[$deviceId]
    }

    $risk = Get-SignInRisk -AppId $signIn.appId -AppName $signIn.appDisplayName -Upn $signIn.userPrincipalName -ServiceDomains $ServiceAccountDomains

    [PSCustomObject]@{
        Timestamp              = $signIn.createdDateTime
        UserPrincipalName      = $signIn.userPrincipalName
        UserDisplayName        = $signIn.userDisplayName
        SignInResult           = if ($signIn.status.errorCode -eq 0) { 'Success' } else { "Failure ($($signIn.status.failureReason))" }
        AttackerIP             = $signIn.ipAddress
        City                   = $signIn.location.city
        Country                = $signIn.location.countryOrRegion
        AppGranted             = $signIn.appDisplayName
        AppId                  = $signIn.appId
        VictimDeviceId         = $deviceId
        VictimDeviceName       = $signIn.deviceDetail.displayName
        VictimDeviceOS         = $signIn.deviceDetail.operatingSystem
        IntuneDeviceName       = $intuneDevice.deviceName
        IntuneOS               = $intuneDevice.operatingSystem
        IntuneOSVersion        = $intuneDevice.osVersion
        IntuneCompliance       = $intuneDevice.complianceState
        IntuneLastSync         = $intuneDevice.lastSyncDateTime
        IntuneManagementState  = $intuneDevice.managementState
        RiskLevelDuringSignIn  = $signIn.riskLevelDuringSignIn
        RiskLevelAggregated    = $signIn.riskLevelAggregated
        ConditionalAccess      = $signIn.conditionalAccessStatus
        ClientApp              = $signIn.clientAppUsed
        AuthProtocol           = $signIn.authenticationProtocol
        Risk                   = $risk
    }
}

#endregion

#region --- Export CSV ---

# Resolve base path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $ExportPath) {
    $ExportPath = "$env:USERPROFILE\Desktop\DeviceCodePhishingReport_$timestamp"
}
# Strip extension if user included one
$ExportPath = [System.IO.Path]::Combine(
    [System.IO.Path]::GetDirectoryName($ExportPath),
    [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
)

$csvPath  = "$ExportPath.csv"
$htmlPath = "$ExportPath.html"

$results | Select-Object Timestamp,UserPrincipalName,UserDisplayName,SignInResult,AttackerIP,City,Country,AppGranted,AppId,VictimDeviceId,VictimDeviceName,VictimDeviceOS,IntuneDeviceName,IntuneOS,IntuneOSVersion,IntuneCompliance,IntuneLastSync,IntuneManagementState,RiskLevelDuringSignIn,RiskLevelAggregated,ConditionalAccess,ClientApp,AuthProtocol |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

#endregion

#region --- Export HTML ---

if (-not $NoHtml) {
    Write-Host "Generating HTML report..." -ForegroundColor Gray

    $successful    = @($results | Where-Object { $_.SignInResult -eq 'Success' })
    $uniqueUsers   = @($results | Select-Object -ExpandProperty UserPrincipalName -Unique)
    $uniqueCountry = @($results | Select-Object -ExpandProperty Country -Unique | Where-Object { $_ })
    $highCount     = @($results | Where-Object { $_.Risk -eq 'high' }).Count
    $medCount      = @($results | Where-Object { $_.Risk -eq 'medium' }).Count
    $lowCount      = @($results | Where-Object { $_.Risk -eq 'low' }).Count

    $scopeLabel = if ($groupMemberUPNs -ne $null) {
        if ($GroupName) { $GroupName } else { $GroupId }
    } else { 'Whole tenant' }

    $generatedDate = Get-Date -Format 'dd MMMM yyyy HH:mm'
    $lookbackStart = (Get-Date).AddDays(-$LookbackDays).ToString('dd MMM yyyy')
    $lookbackEnd   = (Get-Date).ToString('dd MMM yyyy')

    # Build JS data array
    $jsRows = ($results | ForEach-Object {
        $r = $_
        $tsClean  = ($r.Timestamp -replace '"', '\"')
        $upnClean = ($r.UserPrincipalName -replace "'", "\'")
        $nmClean  = ($r.UserDisplayName -replace "'", "\'" -replace '"', '\"')
        $appClean = ($r.AppGranted -replace "'", "\'" -replace '"', '\"')
        $ipClean  = ($r.AttackerIP -replace '"', '\"')
        $devClean = ($r.VictimDeviceName -replace '"', '\"')
        $osClean  = ($r.VictimDeviceOS -replace '"', '\"')
        $iDevClean = ($r.IntuneDeviceName -replace '"', '\"')
        $iComply  = if ($r.IntuneCompliance) { $r.IntuneCompliance } else { '' }
        $ca       = if ($r.ConditionalAccess) { $r.ConditionalAccess } else { '' }
        $rd       = if ($r.RiskLevelDuringSignIn) { $r.RiskLevelDuringSignIn } else { 'none' }
        $country  = if ($r.Country) { $r.Country } else { '' }
        $city     = ($r.City -replace '"', '\"')
        $appId    = if ($r.AppId) { $r.AppId.Substring(0, [Math]::Min(8, $r.AppId.Length)) } else { '' }
        "{ts:`"$tsClean`",upn:`"$upnClean`",name:`"$nmClean`",ip:`"$ipClean`",city:`"$city`",country:`"$country`",app:`"$appClean`",appId:`"$appId`",device:`"$devClean`",os:`"$osClean`",iDevice:`"$iDevClean`",iComply:`"$iComply`",riskDuring:`"$rd`",ca:`"$ca`",risk:`"$($r.Risk)`"}"
    }) -join ",`n"

    $countryFlagMap = '{"DE":"🇩🇪","US":"🇺🇸","IT":"🇮🇹","BR":"🇧🇷","JP":"🇯🇵","PH":"🇵🇭","PT":"🇵🇹","GB":"🇬🇧","HK":"🇭🇰","ES":"🇪🇸","CO":"🇨🇴","NL":"🇳🇱","IN":"🇮🇳","BE":"🇧🇪","FR":"🇫🇷","SA":"🇸🇦","CL":"🇨🇱","AE":"🇦🇪","CA":"🇨🇦","AU":"🇦🇺","SG":"🇸🇬","CN":"🇨🇳","MX":"🇲🇽","AR":"🇦🇷","ZA":"🇿🇦","NG":"🇳🇬","RU":"🇷🇺","UA":"🇺🇦","PL":"🇵🇱","SE":"🇸🇪","NO":"🇳🇴","CH":"🇨🇭","AT":"🇦🇹","IE":"🇮🇪","FI":"🇫🇮","DK":"🇩🇰","TR":"🇹🇷","IL":"🇮🇱","KR":"🇰🇷"}'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Device Code Phishing Report -- $generatedDate</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;color:#cbd5e1;min-height:100vh}
.rpt-header{background:linear-gradient(135deg,#1e1b4b 0%,#0f172a 100%);padding:32px 48px 28px;border-bottom:1px solid #1e3a5f}
.rpt-title{font-size:22px;font-weight:700;color:#f8fafc;letter-spacing:-.3px;display:flex;align-items:center;gap:12px;margin-bottom:8px}
.rpt-meta{font-size:13px;color:#64748b;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.rpt-sep{color:#334155}
.stats-bar{display:flex;gap:16px;padding:24px 48px;background:#0f172a;border-bottom:1px solid #1e293b;flex-wrap:wrap}
.stat-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px 24px;flex:1;min-width:130px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.s1::before{background:#6366f1}.s2::before{background:#ef4444}.s3::before{background:#f59e0b}.s4::before{background:#22c55e}
.stat-n{font-size:30px;font-weight:700;color:#f8fafc}
.stat-l{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#64748b;margin-top:4px;font-weight:500}
.risk-section{display:flex;gap:16px;padding:24px 48px;flex-wrap:wrap;border-bottom:1px solid #1e293b}
.risk-card{flex:1;min-width:200px;border-radius:12px;padding:20px 24px;border:1px solid}
.rh{background:rgba(239,68,68,.07);border-color:#991b1b}
.rm{background:rgba(245,158,11,.07);border-color:#92400e}
.rl{background:rgba(34,197,94,.07);border-color:#166534}
.risk-count{font-size:28px;font-weight:700;color:#f8fafc}
.risk-label{font-size:13px;font-weight:600;margin-top:2px}
.rh .risk-label{color:#f87171}.rm .risk-label{color:#fbbf24}.rl .risk-label{color:#4ade80}
.risk-desc{font-size:12px;color:#64748b;margin-top:6px;line-height:1.5}
.table-section{padding:24px 48px 64px}
.controls{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
input[type=search],select{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:8px 14px;border-radius:8px;font-size:13px;outline:none}
input[type=search]{flex:1;min-width:220px}
select option{background:#1e293b}
.tbl-wrap{overflow-x:auto;border-radius:10px;border:1px solid #1e293b}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:900px}
thead th{background:#1e293b;padding:11px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:1px solid #334155;white-space:nowrap;cursor:pointer}
thead th:hover{color:#e2e8f0}
td{padding:10px 14px;border-bottom:1px solid #0f172a;vertical-align:top;line-height:1.4}
.row-high td{background:rgba(239,68,68,.06)}.row-medium td{background:rgba(245,158,11,.06)}.row-low td{background:rgba(255,255,255,.015)}
.row-high:hover td{background:rgba(239,68,68,.12)}.row-medium:hover td{background:rgba(245,158,11,.12)}.row-low:hover td{background:#1e293b}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px}
.bh{background:#991b1b;color:#fecaca}.bm{background:#78350f;color:#fde68a}.bl{background:#14532d;color:#bbf7d0}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block}
.bh .dot{background:#f87171}.bm .dot{background:#fbbf24}.bl .dot{background:#4ade80}
.upn{color:#93c5fd;font-family:monospace;font-size:12px}
.dname{color:#94a3b8;font-size:11px;margin-top:2px}
.ip-v{font-family:monospace;font-size:12px;color:#a78bfa}
.loc{color:#64748b;font-size:12px}
.tbl-cnt{font-size:13px;color:#64748b;margin-bottom:10px}
.tbl-cnt span{color:#f8fafc;font-weight:600}
.footer{text-align:center;padding:20px;color:#334155;font-size:12px;border-top:1px solid #1e293b}
.footer a{color:#475569}
@media(max-width:768px){.stats-bar,.risk-section,.table-section,.rpt-header{padding-left:16px;padding-right:16px}}
</style>
</head>
<body>
<div class="rpt-header">
  <div class="rpt-title">
    <svg width="28" height="28" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="7" fill="#4f46e5"/><path d="M8 20l4-8 3 6 2-3 3 5" stroke="#e0e7ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/><circle cx="22" cy="10" r="3" stroke="#e0e7ff" stroke-width="2" fill="none"/><line x1="22" y1="13" x2="22" y2="18" stroke="#e0e7ff" stroke-width="2" stroke-linecap="round"/></svg>
    Device Code Phishing -- Investigation Report
  </div>
  <div class="rpt-meta">
    <span>Scope: $scopeLabel</span><span class="rpt-sep">·</span>
    <span>$LookbackDays-day lookback ($lookbackStart - $lookbackEnd)</span><span class="rpt-sep">·</span>
    <span>Generated $generatedDate</span><span class="rpt-sep">·</span>
    <span style="color:#f59e0b;font-weight:600">All $($results.Count) events show Success -- token was issued</span>
  </div>
</div>
<div class="stats-bar">
  <div class="stat-card s1"><div class="stat-n">$($results.Count)</div><div class="stat-l">Total Events</div></div>
  <div class="stat-card s2"><div class="stat-n" style="color:#f87171">$($successful.Count)</div><div class="stat-l">Successful</div></div>
  <div class="stat-card s3"><div class="stat-n">$($uniqueUsers.Count)</div><div class="stat-l">Unique Users</div></div>
  <div class="stat-card s4"><div class="stat-n">$($uniqueCountry.Count)</div><div class="stat-l">Countries</div></div>
</div>
<div class="risk-section">
  <div class="risk-card rh"><div style="font-size:20px;margin-bottom:4px">&#x1F534;</div><div class="risk-count">$highCount</div><div class="risk-label">Investigate</div><div class="risk-desc">Unknown or suspicious app. Verify these users and revoke sessions if not authorised.</div></div>
  <div class="risk-card rm"><div style="font-size:20px;margin-bottom:4px">&#x1F7E1;</div><div class="risk-count">$medCount</div><div class="risk-label">Verify</div><div class="risk-desc">Service or room accounts, or custom internal apps. Confirm these are authorised.</div></div>
  <div class="risk-card rl"><div style="font-size:20px;margin-bottom:4px">&#x1F7E2;</div><div class="risk-count">$lowCount</div><div class="risk-label">Likely Fine</div><div class="risk-desc">Known Microsoft admin and developer tools that legitimately use device code flow.</div></div>
</div>
<div class="table-section">
  <div class="controls">
    <input type="search" id="srch" placeholder="Search user, IP, app, device..." oninput="render()">
    <select id="fRisk" onchange="render()"><option value="">All Risk Levels</option><option value="high">&#x1F534; Investigate</option><option value="medium">&#x1F7E1; Verify</option><option value="low">&#x1F7E2; Likely Fine</option></select>
    <select id="fCountry" onchange="render()"><option value="">All Countries</option></select>
    <select id="fApp" onchange="render()"><option value="">All Apps</option></select>
  </div>
  <div class="tbl-cnt">Showing <span id="cntN">$($results.Count)</span> of $($results.Count) events</div>
  <div class="tbl-wrap"><table>
    <thead><tr>
      <th onclick="sortBy('ts')">Date / Time</th>
      <th onclick="sortBy('upn')">User</th>
      <th onclick="sortBy('app')">App Granted</th>
      <th onclick="sortBy('risk')">Risk</th>
      <th onclick="sortBy('ip')">IP / Location</th>
      <th onclick="sortBy('device')">Device</th>
      <th onclick="sortBy('iComply')">Intune</th>
      <th onclick="sortBy('ca')">CA</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table></div>
</div>
<div class="footer">
  Generated by <a href="https://github.com/Imran76Awan/Daily-Tasks/tree/main/device-code-phishing-microsoft-365-entra" target="_blank">Get-DeviceCodePhishingReport.ps1</a>
  &nbsp;·&nbsp; Read-only Graph API query &nbsp;·&nbsp; No changes made to the tenant
  &nbsp;·&nbsp; <a href="https://endpointweekly.com/blog/device-code-phishing-microsoft-365-entra.html" target="_blank">endpointweekly.com</a>
</div>
<script>
const ROWS=[$jsRows];
const FLAGS=$countryFlagMap;
const RO={high:0,medium:1,low:2};
let sCol='risk',sDir=1;
function sortBy(c){if(sCol===c)sDir*=-1;else{sCol=c;sDir=1;}render();}
function render(){
  const q=(document.getElementById('srch').value||'').toLowerCase();
  const fR=document.getElementById('fRisk').value;
  const fC=document.getElementById('fCountry').value;
  const fA=document.getElementById('fApp').value;
  let rows=[...ROWS];
  if(q)rows=rows.filter(r=>(r.upn+r.name+r.ip+r.city+r.app+r.device+r.iDevice).toLowerCase().includes(q));
  if(fR)rows=rows.filter(r=>r.risk===fR);
  if(fC)rows=rows.filter(r=>r.country===fC);
  if(fA)rows=rows.filter(r=>r.app===fA);
  rows.sort((a,b)=>{let va=sCol==='risk'?RO[a.risk]??9:a[sCol]||'';let vb=sCol==='risk'?RO[b.risk]??9:b[sCol]||'';return va<vb?-sDir:va>vb?sDir:0;});
  document.getElementById('cntN').textContent=rows.length;
  const bm={high:'<span class="badge bh"><span class="dot"></span>Investigate</span>',medium:'<span class="badge bm"><span class="dot"></span>Verify</span>',low:'<span class="badge bl"><span class="dot"></span>Fine</span>'};
  const cm={compliant:'<span style="color:#4ade80;font-weight:600;font-size:12px">&#x2713; Compliant</span>',configManager:'<span style="color:#94a3b8;font-size:12px">Managed</span>'};
  document.getElementById('tbody').innerHTML=rows.map(r=>{
    const flag=FLAGS[r.country]||'';
    const comply=cm[r.iComply]||'<span style="color:#475569;font-size:12px;font-style:italic">not in Intune</span>';
    const iDev=r.iDevice?`<div style="font-size:11px;color:#64748b;margin-top:2px">Intune: `+r.iDevice+`</div>`:'';
    const rDur=r.riskDuring==='high'?`<div style="margin-top:3px"><span style="background:#7f1d1d;color:#fca5a5;font-size:10px;padding:1px 6px;border-radius:4px;font-weight:600">&#x26A0; Entra flagged HIGH</span></div>`:'';
    const ca=r.ca==='success'?'<span style="color:#4ade80;font-size:11px">&#x2713; Enforced</span>':r.ca==='notApplied'?'<span style="color:#475569;font-size:11px">-- not applied</span>':'';
    return `<tr class="row-`+r.risk+`"><td><span style="font-family:monospace;font-size:12px;color:#94a3b8">`+r.ts+`</span></td><td><div class="upn">`+r.upn+`</div><div class="dname">`+r.name+`</div></td><td><div style="font-weight:500;color:#e2e8f0">`+r.app+`</div><div style="color:#475569;font-size:11px;font-family:monospace">`+r.appId+`...</div></td><td>`+bm[r.risk]+rDur+`</td><td><div class="ip-v">`+r.ip+`</div><div class="loc">`+flag+' '+r.city+', '+r.country+`</div></td><td><div style="font-weight:500;color:#e2e8f0">`+(r.device||'<span style="color:#334155;font-style:italic">unknown</span>')+`</div><div style="color:#64748b;font-size:11px">`+r.os+`</div>`+iDev+`</td><td>`+comply+`</td><td>`+ca+`</td></tr>`;
  }).join('');
}
(function(){
  const cs=document.getElementById('fCountry');const as=document.getElementById('fApp');
  [...new Set(ROWS.map(r=>r.country))].filter(Boolean).sort().forEach(c=>{const o=document.createElement('option');o.value=c;o.textContent=(FLAGS[c]||'')+' '+c;cs.appendChild(o);});
  [...new Set(ROWS.map(r=>r.app))].sort().forEach(a=>{const o=document.createElement('option');o.value=a;o.textContent=a;as.appendChild(o);});
})();
render();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
}

#endregion

#region --- Summary ---

$successful    = @($results | Where-Object { $_.SignInResult -eq 'Success' })
$uniqueUsers   = @($results | Select-Object -ExpandProperty UserPrincipalName -Unique)
$uniqueDevices = @($results | Where-Object { $_.VictimDeviceId } | Select-Object -ExpandProperty VictimDeviceId -Unique)
$uniqueCountry = @($results | Select-Object -ExpandProperty Country -Unique | Where-Object { $_ })
$managed       = @($results | Where-Object { $_.IntuneDeviceName })
$highRisk      = @($results | Where-Object { $_.Risk -eq 'high' })

Write-Host ""
$scopeLabel2 = if ($groupMemberUPNs -ne $null) { if ($GroupName) { $GroupName } else { $GroupId } } else { "Whole tenant" }
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Device Code Phishing  -  Investigation Summary" -ForegroundColor Cyan
Write-Host " Scope: $scopeLabel2" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Total events found:        $($results.Count)"
Write-Host "  Successful sign-ins:       $($successful.Count)" -ForegroundColor $(if ($successful.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Unique users:              $($uniqueUsers.Count)"
Write-Host "  Unique devices:            $($uniqueDevices.Count)"
Write-Host "  Intune-managed devices:    $($managed.Count)"
Write-Host "  Countries in sign-in IPs:  $($uniqueCountry -join ', ')"
Write-Host ""
Write-Host "  Risk breakdown:"
Write-Host "    HIGH   (Investigate): $($highRisk.Count)" -ForegroundColor $(if ($highRisk.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "    MEDIUM (Verify):      $(@($results | Where-Object {$_.Risk -eq 'medium'}).Count)" -ForegroundColor Yellow
Write-Host "    LOW    (Likely Fine): $(@($results | Where-Object {$_.Risk -eq 'low'}).Count)" -ForegroundColor Green
Write-Host ""

if ($highRisk.Count -gt 0) {
    Write-Host "HIGH-RISK SIGN-INS - VERIFY OR REVOKE IMMEDIATELY:" -ForegroundColor Red
    $highRisk | Select-Object -ExpandProperty UserPrincipalName -Unique | ForEach-Object {
        Write-Host "  !! $_" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "ACTION REQUIRED for each user above:" -ForegroundColor Yellow
    Write-Host "  1. Revoke sessions: Entra admin center > Users > [user] > Revoke sessions" -ForegroundColor Yellow
    Write-Host "  2. Reset password and force MFA re-registration" -ForegroundColor Yellow
    Write-Host "  3. Review inbox rules: Get-InboxRule -Mailbox <UPN>" -ForegroundColor Yellow
    Write-Host "  4. Audit OAuth app consents granted around the incident window" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Reports exported:" -ForegroundColor Green
Write-Host "  CSV:  $csvPath" -ForegroundColor Green
if (-not $NoHtml) {
    Write-Host "  HTML: $htmlPath" -ForegroundColor Cyan
    Write-Host "        (Open in any browser for the colour-coded investigation report)" -ForegroundColor Gray
}

#endregion
