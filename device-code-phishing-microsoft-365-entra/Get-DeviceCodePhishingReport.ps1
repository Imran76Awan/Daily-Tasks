<#
.SYNOPSIS
    Queries Entra ID sign-in logs for device code flow events and correlates with Intune device records.

.DESCRIPTION
    Uses Microsoft Graph to retrieve all sign-in events where AuthenticationProtocol = deviceCode
    over a configurable lookback window. For each hit, attempts to correlate the signing device
    with an Intune managed device record using the Azure AD Device ID from the sign-in log.

    By default runs against the whole tenant. Use -GroupId or -GroupName to scope the report
    to members of a specific Entra ID group (e.g. a department, a pilot ring, or an exec group).

    Exports a CSV report containing:
      - User (UPN and display name)
      - Sign-in result (Success or Failure reason)
      - IP address and location (typically the attacker's polling IP on a compromised sign-in)
      - App that received the token
      - Device that completed the sign-in (victim's device - name, OS, Intune compliance state)
      - Risk level and Conditional Access result

    Run this against a tenant or group to answer: which users and devices were targeted or compromised?

.PARAMETER LookbackDays
    Days of sign-in history to query. Default: 30.
    Note: Entra ID retains sign-in logs for 30 days (P1/P2) or 7 days (free tier).
    For longer retention, use Microsoft Sentinel.

.PARAMETER GroupId
    Object ID of an Entra ID group. When specified, only sign-ins for members of this group
    are included. Takes precedence over -GroupName if both are supplied.

.PARAMETER GroupName
    Display name of an Entra ID group. The script resolves it to an Object ID automatically.
    If multiple groups share the same display name, use -GroupId instead.

.PARAMETER ExportPath
    Full path for the output CSV. Defaults to Desktop with a date-stamped filename.

.PARAMETER TenantId
    Entra ID tenant ID or domain (e.g. contoso.onmicrosoft.com). Required for certificate auth.

.PARAMETER ClientId
    App registration (service principal) client ID. Required for certificate auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate installed in the local certificate store.
    Required for certificate auth. Use with -TenantId and -ClientId to avoid interactive sign-in.

.PARAMETER SuccessfulOnly
    If specified, only exports successful device code sign-ins (ErrorCode = 0).
    Use this to focus on confirmed compromises rather than blocked/failed attempts.

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.DeviceManagement,
              Microsoft.Graph.Groups (for group-scoped runs)
    Scopes:   AuditLog.Read.All, DeviceManagementManagedDevices.Read.All, GroupMember.Read.All
    Blog:     https://endpointweekly.com/blog/device-code-phishing-microsoft-365-entra.html

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" -LookbackDays 30
    Connects via certificate (no browser prompt) and queries last 30 days across the whole tenant.

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -CertificateThumbprint "AABBCCDDEEFF..." -GroupName "Finance" -LookbackDays 30
    Cert auth, scoped to the Finance group.

.EXAMPLE
    .\Get-DeviceCodePhishingReport.ps1 -GroupName "Finance" -LookbackDays 30
    Interactive sign-in fallback (device code - works in any terminal).
#>

[CmdletBinding()]
param(
    [int]$LookbackDays = 30,
    [string]$GroupId,
    [string]$GroupName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$ExportPath = "$env:USERPROFILE\Desktop\DeviceCodePhishingReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$SuccessfulOnly
)

#region --- Prerequisites ---

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.DeviceManagement'
)

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod..." -ForegroundColor Cyan
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    }
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

$groupMemberUPNs = $null  # null = no group filter (whole tenant)

if ($GroupId -or $GroupName) {

    if (-not $GroupId) {
        Write-Host "Resolving group name '$GroupName'..." -ForegroundColor Gray
        $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop | Select-Object -First 1
        if (-not $group) {
            Write-Warning "Group '$GroupName' not found. Check the display name and try again."
            return
        }
        $GroupId = $group.Id
        Write-Host "Resolved to Group ID: $GroupId" -ForegroundColor Gray
    }

    Write-Host "Loading group members..." -ForegroundColor Gray
    try {
        $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
        $groupMemberUPNs = @{}
        foreach ($m in $members) {
            # Members can be users, groups, or service principals  -  only users have UPN
            $user = Get-MgUser -UserId $m.Id -Property "userPrincipalName" -ErrorAction SilentlyContinue
            if ($user.UserPrincipalName) {
                $groupMemberUPNs[$user.UserPrincipalName.ToLower()] = $true
            }
        }
        Write-Host "Group contains $($groupMemberUPNs.Count) user(s). Sign-in results will be filtered to these members." -ForegroundColor Gray
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

# Use Invoke-MgGraphRequest against the beta endpoint directly.
# authenticationProtocol is a beta-only filter property and is not available on v1.0.
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
    Write-Host "Ensure the app registration has AuditLog.Read.All application permission in Entra ID." -ForegroundColor Yellow
    return
}

Write-Host "Found $($signIns.Count) device code sign-in event(s) across the tenant." -ForegroundColor $(if ($signIns.Count -gt 0) { 'Yellow' } else { 'Green' })

# Apply group filter if scoped
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

# Cache Intune devices to avoid repeated Graph calls for the same device ID
$intuneCache = @{}

$results = foreach ($signIn in $signIns) {

    $deviceId = $signIn.deviceDetail.deviceId
    $intuneDevice = $null

    if ($deviceId -and $deviceId -ne "00000000-0000-0000-0000-000000000000") {
        if (-not $intuneCache.ContainsKey($deviceId)) {
            try {
                $hit = Get-MgDeviceManagementManagedDevice `
                    -Filter "azureADDeviceId eq '$deviceId'" `
                    -Property "deviceName,operatingSystem,osVersion,lastSyncDateTime,complianceState,managementState" `
                    -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                $intuneCache[$deviceId] = $hit
            }
            catch {
                $intuneCache[$deviceId] = $null
            }
        }
        $intuneDevice = $intuneCache[$deviceId]
    }

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
        # Device that completed the sign-in (victim's machine)
        VictimDeviceId         = $deviceId
        VictimDeviceName       = $signIn.deviceDetail.displayName
        VictimDeviceOS         = $signIn.deviceDetail.operatingSystem
        # Intune record (if managed)
        IntuneDeviceName       = $intuneDevice.DeviceName
        IntuneOS               = $intuneDevice.OperatingSystem
        IntuneOSVersion        = $intuneDevice.OsVersion
        IntuneCompliance       = $intuneDevice.ComplianceState
        IntuneLastSync         = $intuneDevice.LastSyncDateTime
        IntuneManagementState  = $intuneDevice.ManagementState
        # Risk signals
        RiskLevelDuringSignIn  = $signIn.riskLevelDuringSignIn
        RiskLevelAggregated    = $signIn.riskLevelAggregated
        ConditionalAccess      = $signIn.conditionalAccessStatus
        ClientApp              = $signIn.clientAppUsed
        AuthProtocol           = $signIn.authenticationProtocol
    }
}

#endregion

#region --- Export and summary ---

$results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

$successful     = $results | Where-Object { $_.SignInResult -eq 'Success' }
$uniqueUsers    = @($results | Select-Object -ExpandProperty UserPrincipalName -Unique)
$uniqueDevices  = @($results | Where-Object { $_.VictimDeviceId } | Select-Object -ExpandProperty VictimDeviceId -Unique)
$uniqueCountries = @($results | Select-Object -ExpandProperty Country -Unique)
$managed        = @($results | Where-Object { $_.IntuneDeviceName })

Write-Host ""
$scopeLabel = if ($groupMemberUPNs -ne $null) { "Group: $(if ($GroupName) { $GroupName } else { $GroupId })" } else { "Whole tenant" }
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Device Code Phishing  -  Investigation Summary" -ForegroundColor Cyan
Write-Host " Scope: $scopeLabel" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Total events found:        $($results.Count)"
Write-Host "  Successful sign-ins:       $($successful.Count)" -ForegroundColor $(if ($successful.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Unique users:              $($uniqueUsers.Count)"
Write-Host "  Unique devices:            $($uniqueDevices.Count)"
Write-Host "  Intune-managed devices:    $($managed.Count)"
Write-Host "  Countries in sign-in IPs:  $($uniqueCountries -join ', ')"
Write-Host ""

if ($successful.Count -gt 0) {
    Write-Host "USERS WITH SUCCESSFUL DEVICE CODE SIGN-INS (token was issued):" -ForegroundColor Red
    $successful | Select-Object -ExpandProperty UserPrincipalName -Unique | ForEach-Object {
        Write-Host "  !! $_" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "ACTION REQUIRED for each user above:" -ForegroundColor Yellow
    Write-Host "  1. Revoke sessions: Entra admin center > Users > [user] > Revoke sessions" -ForegroundColor Yellow
    Write-Host "  2. Reset password and force MFA re-registration" -ForegroundColor Yellow
    Write-Host "  3. Review inbox rules: Get-InboxRule -Mailbox <UPN>" -ForegroundColor Yellow
    Write-Host "  4. Audit OAuth app consents granted around the incident window" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Full report exported to: $ExportPath" -ForegroundColor Green

#endregion
