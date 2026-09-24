<#
.SYNOPSIS
    Read-only Microsoft Graph report of the two Admin tasks sources that actually expose a public
    Graph API: pending EPM elevation requests and pending Multi Admin Approval (MAA) operation
    approval requests.

.DESCRIPTION
    Get-IntuneAdminTasksReport.ps1 is the companion script for the EndpointWeekly post on the
    Intune "Admin tasks" centralized approval queue. Intune's Admin tasks pane in the admin center
    aggregates up to four sources (EPM elevation requests, Defender security tasks, Multi Admin
    Approval requests, and the now-retired Device Offboarding Agent) into one UI-only view. There is
    no single Graph API behind that aggregation, so this script queries the two sources that do have
    a documented Graph surface, directly:

      1. EPM support-approved elevation requests
         GET /deviceManagement/elevationRequests (beta resource: privilegeManagementElevationRequest)
         Filtered to status eq 'pending'. An approved EPM request stays actionable on the device for
         24 hours from approval (requestExpiryDateTime) before it expires.

      2. Multi Admin Approval (MAA) operation approval requests
         GET /deviceManagement/operationApprovalRequests (beta resource: operationApprovalRequest)
         Filtered to status eq 'needsApproval'. An MAA request that nobody actions expires per its
         own expirationDateTime, commonly around 72 hours after creation, though the exact offset is
         set server-side per policy and is not a fixed constant this script can rely on - the report
         below always calculates and shows the real expirationDateTime returned by Graph rather than
         assuming a fixed window.

    HONEST SCOPE NOTE: Defender security tasks and the retired Device Offboarding Agent are NOT
    covered by this script, because neither has a documented public Microsoft Graph endpoint as of
    this writing. A clean (exit 0) run of this script is NOT proof the full Admin tasks queue in the
    portal is empty - it only proves the two sources below are empty. Check
    Endpoint security > Security tasks in the Intune admin center directly for Defender security
    tasks; this script cannot reach that surface and does not pretend otherwise.

    This script is strictly READ-ONLY. It calls Invoke-MgGraphRequest -Method GET exclusively. It
    never calls Approve, Deny, Reject, Cancel, or any other write/action verb against either
    endpoint, and it never modifies any tenant, policy, or request state.

.PARAMETER TenantId
    Entra ID tenant ID (GUID or verified domain) for app-only certificate authentication. Required
    together with -ClientId and -CertificateThumbprint. Mutually exclusive with -UseDeviceCode.

.PARAMETER ClientId
    App registration (application) ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate installed in the local certificate store that is associated with
    the app registration used for app-only authentication.

.PARAMETER UseDeviceCode
    Switch. Uses interactive delegated device code sign-in instead of app-only certificate
    authentication. Useful for a quick manual run from an admin workstation.

.PARAMETER CsvPath
    Optional. Full path to a CSV file. When supplied, every pending/needs-approval item found across
    both sources is exported to this path in addition to the console report.

.NOTES
    Author        : Imran Awan
    Blog post     : https://endpointweekly.com/blog/microsoft-intune-admin-tasks-centralized-approval-queue.html
    Repo          : https://github.com/Imran76Awan/Daily-Tasks/tree/main/microsoft-intune-admin-tasks-centralized-approval-queue
    Requires      : Microsoft.Graph.Authentication module (Connect-MgGraph / Invoke-MgGraphRequest)
    Graph scopes  : DeviceManagementConfiguration.Read.All (elevationRequests),
                    DeviceManagementRBAC.Read.All (operationApprovalRequests)
    Read-only     : Yes. GET requests only. No tenant, policy, or request state is modified.
    Confirmed vs live-tenant-only:
        - The property names and enum values used below (status, requestExpiryDateTime,
          applicationDetail.fileName for EPM; status, requestDateTime, expirationDateTime,
          requestor.user.displayName, requestor.device.displayName for MAA) are taken directly from
          the current Microsoft Graph beta resource reference pages for
          privilegeManagementElevationRequest and operationApprovalRequest. They are confirmed
          against documentation, not against a live tenant.
        - What is NOT confirmed by documentation alone and needs a live tenant: whether the exact
          permission scopes above are sufficient in practice for an app-only principal (Microsoft's
          docs for these two beta resources do not spell out the app permission name the same way
          v1.0 resources do), whether both beta endpoints are enabled and reachable in every tenant,
          and whether MAA's expirationDateTime offset behaves as documented when returned by GET vs.
          only being meaningful on request creation. Treat every count and status in this report as
          accurate to what Graph returned at run time, and validate the permission scopes against
          your own app registration's actual token if either query returns an authorization error
          rather than an empty result.
    Exit codes    : 0 = ran cleanly, no pending EPM elevation requests and no MAA requests awaiting
                        approval were found
                    1 = ran cleanly, but one or more pending/needs-approval items were found (this is
                        informational, not a script failure - it means there is something in the
                        queue for an admin to review)
                    2 = a connection, authentication, or Graph query error occurred and the report
                        could not be completed reliably

.EXAMPLE
    .\Get-IntuneAdminTasksReport.ps1 -TenantId "<tenant-id>" -ClientId "<app-id>" -CertificateThumbprint "<thumbprint>"

    Runs the report using app-only (certificate) authentication - the recommended method for a
    scheduled or unattended run, e.g. from a daily scheduled task.

.EXAMPLE
    .\Get-IntuneAdminTasksReport.ps1 -UseDeviceCode -CsvPath "C:\Reports\intune-admin-tasks.csv"

    Runs the report interactively using device code sign-in and exports every pending/needs-approval
    item found to CSV.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
    [switch]$UseDeviceCode,

    [Parameter()]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor DarkGray
}

function Get-AllGraphPages {
    # Follows @odata.nextLink until every page of a Graph collection has been retrieved.
    # GET only - never used against a write endpoint in this script.
    param([Parameter(Mandatory = $true)][string]$Uri)

    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    while ($null -ne $nextUri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        }
        catch {
            Write-Warning "Graph GET failed for '$nextUri': $($_.Exception.Message)"
            $script:hadError = $true
            return $results
        }
        if ($response.value) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        $nextUri = $response.'@odata.nextLink'
    }
    return $results
}

# --- Connect ---------------------------------------------------------------------------------

Write-Section "Connecting to Microsoft Graph (read-only)"

try {
    if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome
        Write-Host "Connected using app-only certificate authentication." -ForegroundColor Green
    }
    else {
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All", "DeviceManagementRBAC.Read.All" `
            -UseDeviceCode -NoWelcome
        Write-Host "Connected using delegated device code sign-in." -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 2
}

$now = Get-Date

# --- Source 1: EPM support-approved elevation requests ---------------------------------------

Write-Section "1. EPM elevation requests - deviceManagement/elevationRequests (beta)"

$epmFindings = New-Object System.Collections.Generic.List[object]

try {
    $epmRequests = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/elevationRequests?`$filter=status eq 'pending'"
}
catch {
    Write-Warning "Failed to query elevationRequests: $($_.Exception.Message)"
    $script:hadError = $true
    $epmRequests = @()
}

if ($epmRequests.Count -eq 0) {
    Write-Host "No pending EPM elevation requests." -ForegroundColor Green
}
else {
    Write-Host "$($epmRequests.Count) pending EPM elevation request(s):" -ForegroundColor Yellow
    foreach ($req in $epmRequests) {
        $ageHours = $null
        if ($req.requestCreatedDateTime) {
            $ageHours = [math]::Round(($now - [datetime]$req.requestCreatedDateTime).TotalHours, 1)
        }
        $epmFindings.Add([PSCustomObject]@{
            Source                  = 'EPM'
            Status                  = $req.status
            DeviceName               = $req.deviceName
            RequestedBy              = $req.requestedByUserPrincipalName
            FileName                 = $req.applicationDetail.fileName
            Justification            = $req.requestJustification
            RequestCreatedDateTime   = $req.requestCreatedDateTime
            RequestExpiryDateTime    = $req.requestExpiryDateTime
            AgeHours                 = $ageHours
        })
    }
    $epmFindings |
        Select-Object DeviceName, RequestedBy, FileName, AgeHours, RequestExpiryDateTime |
        Format-Table -AutoSize -Wrap | Out-String | Write-Host
}

# --- Source 2: Multi Admin Approval (MAA) operation approval requests -------------------------

Write-Section "2. MAA operation approval requests - deviceManagement/operationApprovalRequests (beta)"

$maaFindings = New-Object System.Collections.Generic.List[object]

try {
    $maaRequests = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests?`$filter=status eq 'needsApproval'"
}
catch {
    Write-Warning "Failed to query operationApprovalRequests: $($_.Exception.Message)"
    $script:hadError = $true
    $maaRequests = @()
}

if ($maaRequests.Count -eq 0) {
    Write-Host "No MAA operation approval requests are awaiting approval." -ForegroundColor Green
}
else {
    Write-Host "$($maaRequests.Count) MAA operation approval request(s) awaiting approval:" -ForegroundColor Yellow
    foreach ($req in $maaRequests) {
        $ageHours = $null
        if ($req.requestDateTime) {
            $ageHours = [math]::Round(($now - [datetime]$req.requestDateTime).TotalHours, 1)
        }
        $maaFindings.Add([PSCustomObject]@{
            Source                = 'MAA'
            Status                 = $req.status
            RequestedByUser         = $req.requestor.user.displayName
            RequestedByDevice       = $req.requestor.device.displayName
            RequestedByApplication  = $req.requestor.application.displayName
            Justification           = $req.requestJustification
            RequestDateTime         = $req.requestDateTime
            ExpirationDateTime      = $req.expirationDateTime
            AgeHours                = $ageHours
        })
    }
    $maaFindings |
        Select-Object RequestedByUser, RequestedByDevice, RequestedByApplication, AgeHours, ExpirationDateTime |
        Format-Table -AutoSize -Wrap | Out-String | Write-Host
}

# --- Honest scope note: what this script does NOT cover --------------------------------------

Write-Section "3. Out of scope for this script"

Write-Host "Defender security tasks and the retired Device Offboarding Agent are NOT included in" -ForegroundColor DarkYellow
Write-Host "this report. Neither has a documented public Microsoft Graph endpoint as of this" -ForegroundColor DarkYellow
Write-Host "writing, so this script has no way to query them. A clean (exit 0) run below is proof" -ForegroundColor DarkYellow
Write-Host "only that the two sources this script CAN reach are empty - check" -ForegroundColor DarkYellow
Write-Host "Endpoint security > Security tasks in the Intune admin center directly for Defender" -ForegroundColor DarkYellow
Write-Host "security tasks; that surface is out of reach for a script relying on public Graph." -ForegroundColor DarkYellow

# --- Summary -----------------------------------------------------------------------------------

Write-Section "Summary"

$allFindings = New-Object System.Collections.Generic.List[object]
foreach ($f in $epmFindings) { $allFindings.Add($f) }
foreach ($f in $maaFindings) { $allFindings.Add($f) }

$oldestAge = $null
if ($allFindings.Count -gt 0) {
    $oldestAge = ($allFindings | Where-Object { $null -ne $_.AgeHours } | Select-Object -ExpandProperty AgeHours | Sort-Object -Descending | Select-Object -First 1)
}

Write-Host "=== Intune Admin Tasks Fleet Report ===" -ForegroundColor Cyan
Write-Host "Generated : $($now.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Source    : deviceManagement/elevationRequests (EPM), deviceManagement/operationApprovalRequests (MAA)"
Write-Host ""
Write-Host "EPM elevation requests - Pending           : $($epmRequests.Count)"
Write-Host "MAA operation approval requests - NeedsApproval : $($maaRequests.Count)"
if ($null -ne $oldestAge) {
    Write-Host "Oldest pending item age (hours)             : $oldestAge  <- compare against each item's own expiry shown above; EPM and MAA expiry offsets are returned per-item, not a fixed constant"
}
else {
    Write-Host "Oldest pending item age (hours)             : n/a (no pending items found)"
}

# --- Optional CSV export ------------------------------------------------------------------------

if ($CsvPath) {
    try {
        $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "Findings exported to $CsvPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to write CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

Write-Section "Done"

if ($script:hadError) {
    Write-Warning "One or more Graph queries failed during this run - review the warnings above. Counts shown may be incomplete."
    Write-Host ""
    Write-Host "Exit code: 2 (connection, authentication, or Graph query error)" -ForegroundColor Red
    exit 2
}
elseif ($allFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "Exit code: 1 (pending items found - review the tables above)" -ForegroundColor Yellow
    exit 1
}
else {
    Write-Host ""
    Write-Host "Exit code: 0 (no errors contacting Graph; no pending EPM or MAA items found)" -ForegroundColor Green
    exit 0
}
