<#
.SYNOPSIS
    Triggers an on-demand Intune remediation ("Run remediation") on every Windows device in an Entra ID group.

.DESCRIPTION
    The Intune admin center documents "Run remediation" as a single-device action, and it is not one of the
    Windows bulk device actions. This script closes that gap by calling the Microsoft Graph action
    initiateOnDemandProactiveRemediation once per device, for every device in a group you name.

    SAFETY DESIGN
      * DRY RUN BY DEFAULT. Without -Execute the script only reads: it resolves the group, the remediation and
        the devices, prints exactly what WOULD happen, and triggers nothing.
      * With -Execute you must still type YES at an interactive prompt that states the device count.
      * -Limit N targets only the first N devices, so you can test on a handful before the full group.
      * Ambiguity stops the run. If more than one group, or more than one remediation, matches the name you gave,
        the script lists the matches and exits. Pass -GroupId / -RemediationId instead.
      * The high-privilege Graph scope (DeviceManagementManagedDevices.PrivilegedOperations.All) is only
        requested when you pass -Execute. A dry run uses read-only scopes.

    WHAT "ACCEPTED" MEANS
      Graph answers 204 No Content when it accepts the request. That is not proof the device ran the script.
      Microsoft documents that a device which is offline, or cannot reach Intune and the Windows Push
      Notification Service (WNS) when the action is sent, does not receive it. Check
      Devices > Scripts and remediations > (your remediation) > Device status afterwards.

    ONE ACTION AT A TIME PER DEVICE
      Microsoft documents that only one Run remediation action can be issued at a time for the same device, and
      that several in a short period can overwrite each other. Do not run this script for two different
      remediations against the same devices back to back.

    The Graph calls to deviceHealthScripts and initiateOnDemandProactiveRemediation use the /beta endpoint,
    because that is where Microsoft documents them. Beta APIs can change.

.PARAMETER GroupName
    Exact display name of the Entra ID group. Use -GroupId if names are not unique in your tenant.

.PARAMETER GroupId
    Object ID (GUID) of the Entra ID group. Use this OR -GroupName.

.PARAMETER RemediationName
    Exact display name of the remediation (script package) under Devices > Scripts and remediations.

.PARAMETER RemediationId
    ID (GUID) of the remediation. Use this OR -RemediationName.

.PARAMETER Execute
    Actually trigger the remediation. Without this switch the script is a read-only dry run.

.PARAMETER Limit
    Trigger only the first N devices (0 = all). Use 3 to 5 for a first test.

.PARAMETER MaxDaysSinceSync
    Skip devices whose last Intune check-in is older than this many days (0 = do not filter). A recent check-in
    is only a hint that a device is reachable. It does not guarantee the action will be delivered.

.PARAMETER IncludeNestedGroups
    Also include devices that are members of nested groups. By default only direct members are used, because
    the Graph "list members" operation is not transitive.

.PARAMETER OutputPath
    Where to write the results CSV when -Execute is used. Default: .\RemediationRun-<timestamp>.csv

.PARAMETER TenantId
    App-only mode: your tenant ID. Use together with -ClientId and -CertificateThumbprint.

.PARAMETER ClientId
    App-only mode: the application (client) ID of an app registration that has been granted, and admin-consented,
    the application permissions listed in the blog post.

.PARAMETER CertificateThumbprint
    App-only mode: thumbprint of the certificate installed for that app registration.

.PARAMETER UseDeviceCode
    Delegated mode: sign in with a device code instead of a browser pop-up.

.EXAMPLE
    .\Invoke-RemediationOnGroup.ps1 -GroupName "Win11 Pilot Laptops" -RemediationName "Reset stale update cache"
    Dry run. Lists the devices that would be targeted. Triggers nothing.

.EXAMPLE
    .\Invoke-RemediationOnGroup.ps1 -GroupName "Win11 Pilot Laptops" -RemediationName "Reset stale update cache" -Execute -Limit 5
    Test batch: triggers the remediation on the first 5 devices after you type YES.

.EXAMPLE
    .\Invoke-RemediationOnGroup.ps1 -GroupId 11111111-2222-3333-4444-555555555555 -RemediationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee -Execute -MaxDaysSinceSync 7
    Full group, skipping devices that have not checked in for 7 days.

.EXAMPLE
    .\Invoke-RemediationOnGroup.ps1 -GroupName "Win11 Pilot Laptops" -RemediationName "Reset stale update cache" -TenantId <tenant-guid> -ClientId <app-guid> -CertificateThumbprint <thumbprint>
    Dry run using app-only certificate authentication, for unattended use.

.NOTES
    Blog   : https://endpointweekly.com/blog/intune-run-remediation-on-demand-device-group-graph.html
    Needs  : PowerShell 7 (recommended) or Windows PowerShell 5.1, and the Microsoft.Graph.Authentication module.
             The Graph PowerShell SDK is moving toward PowerShell 7 only, so prefer PowerShell 7 for anything long-lived.
    Exit   : 0 = dry run finished, or every request was accepted
             1 = could not start (bad parameters, ambiguous or missing group/remediation, sign-in failure)
             2 = at least one device was not accepted (see the CSV). Never reported as a clean run.
    Test it yourself before you rely on it. It was developed against a mocked Graph and has not been run
    against your tenant.
#>
[CmdletBinding()]
param(
    [string]$GroupName,
    [string]$GroupId,
    [string]$RemediationName,
    [string]$RemediationId,
    [switch]$Execute,
    [ValidateRange(0, 100000)][int]$Limit = 0,
    [ValidateRange(0, 3650)][int]$MaxDaysSinceSync = 0,
    [switch]$IncludeNestedGroups,
    [string]$OutputPath,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [switch]$UseDeviceCode
)

$ErrorActionPreference = 'Stop'

function Stop-Run([string]$Message, [int]$Code = 1) {
    Write-Host ""
    Write-Host "STOPPED: $Message" -ForegroundColor Red
    exit $Code
}

function Test-GuidText([string]$Text) {
    $g = [guid]::Empty
    return [guid]::TryParse($Text, [ref]$g)
}

# One Graph call with a small retry for throttling (429) and transient service errors (503/504).
function Invoke-Graph {
    param([string]$Method, [string]$Uri, [string]$Body)
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType 'application/json'
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        } catch {
            $msg = $_.Exception.Message
            $retryable = ($msg -match '\b(429|503|504)\b') -or ($msg -match 'TooManyRequests|Too Many Requests|ServiceUnavailable|GatewayTimeout')
            if ($retryable -and $attempt -le 4) {
                $wait = [int]([math]::Pow(2, $attempt) * 2)
                Write-Warning "  Graph is throttling or busy (attempt $attempt of 4). Waiting $wait s, then retrying."
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

# Follows @odata.nextLink and returns every item.
function Get-AllPages([string]$Uri) {
    $items = New-Object System.Collections.ArrayList
    while ($Uri) {
        $resp = Invoke-Graph -Method GET -Uri $Uri
        if ($resp.value) { foreach ($v in $resp.value) { [void]$items.Add($v) } }
        $Uri = $resp.'@odata.nextLink'
    }
    return $items.ToArray()
}

# ---------------------------------------------------------------- 1. validate the parameters
if ([bool]$GroupName -eq [bool]$GroupId) { Stop-Run 'Give exactly one of -GroupName or -GroupId.' }
if ([bool]$RemediationName -eq [bool]$RemediationId) { Stop-Run 'Give exactly one of -RemediationName or -RemediationId.' }
if ($GroupId -and -not (Test-GuidText $GroupId)) { Stop-Run '-GroupId is not a valid GUID.' }
if ($RemediationId -and -not (Test-GuidText $RemediationId)) { Stop-Run '-RemediationId is not a valid GUID.' }
$appOnly = [bool]$ClientId -or [bool]$TenantId -or [bool]$CertificateThumbprint
if ($appOnly -and -not ($ClientId -and $TenantId -and $CertificateThumbprint)) {
    Stop-Run 'App-only mode needs all three of -TenantId, -ClientId and -CertificateThumbprint.'
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Stop-Run 'The Microsoft.Graph.Authentication module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ---------------------------------------------------------------- 2. connect (least privilege)
$scopes = @('Group.Read.All', 'GroupMember.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementScripts.Read.All')
if ($Execute) { $scopes += 'DeviceManagementManagedDevices.PrivilegedOperations.All' }

try {
    if ($appOnly) {
        Write-Host "Connecting to Microsoft Graph (app-only, certificate)..."
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Write-Host "Connecting to Microsoft Graph (delegated). Scopes: $($scopes -join ', ')"
        if ($UseDeviceCode) { Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome } else { Connect-MgGraph -Scopes $scopes -NoWelcome }
    }
} catch {
    Stop-Run "Sign-in failed: $($_.Exception.Message)"
}
$ctx = Get-MgContext
if ($ctx) { Write-Host "Connected. Account/app: $($ctx.Account) $($ctx.ClientId)" }

try {
    # ------------------------------------------------------------ 3. resolve the group
    if ($GroupName) {
        Write-Host "Looking up group: $GroupName"
        $esc = $GroupName.Replace("'", "''")
        $f = [uri]::EscapeDataString("displayName eq '$esc'")
        $found = @(Get-AllPages "https://graph.microsoft.com/v1.0/groups?`$filter=$f")
        if ($found.Count -eq 0) { Stop-Run "Group '$GroupName' not found. Check the exact display name in Entra ID." }
        if ($found.Count -gt 1) {
            Write-Host "More than one group is named '$GroupName':" -ForegroundColor Yellow
            $found | ForEach-Object { Write-Host "  - $($_.id)  $($_.displayName)" }
            Stop-Run 'Ambiguous group name. Re-run with -GroupId <id> for the one you mean.'
        }
        $groupIdResolved = $found[0].id
        $groupLabel = $found[0].displayName
    } else {
        $groupIdResolved = $GroupId
        $groupLabel = $GroupId
    }
    Write-Host "Group id: $groupIdResolved"

    $edge = 'members'
    if ($IncludeNestedGroups) { $edge = 'transitiveMembers' }
    $members = @(Get-AllPages "https://graph.microsoft.com/v1.0/groups/$groupIdResolved/${edge}?`$top=999")
    $deviceMembers = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' })
    Write-Host "Group has $($deviceMembers.Count) device member(s) out of $($members.Count) member(s) ($edge)."
    if ($deviceMembers.Count -eq 0) { Stop-Run 'The group has no device members.' }

    # ------------------------------------------------------------ 4. resolve the remediation
    if ($RemediationName) {
        Write-Host "Looking up remediation: $RemediationName"
        $scriptsAll = @(Get-AllPages 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts')
        $matched = @($scriptsAll | Where-Object { $_.displayName -eq $RemediationName })
        if ($matched.Count -eq 0) { Stop-Run "Remediation '$RemediationName' not found. Check the exact name under Devices > Scripts and remediations." }
        if ($matched.Count -gt 1) {
            Write-Host "More than one remediation is named '$RemediationName':" -ForegroundColor Yellow
            $matched | ForEach-Object { Write-Host "  - $($_.id)  $($_.displayName)" }
            Stop-Run 'Ambiguous remediation name. Re-run with -RemediationId <id> for the one you mean.'
        }
        $scriptIdResolved = $matched[0].id
        $scriptLabel = $matched[0].displayName
    } else {
        $scriptIdResolved = $RemediationId
        $scriptLabel = $RemediationId
    }
    Write-Host "Remediation id: $scriptIdResolved"

    # ------------------------------------------------------------ 5. resolve each device to its Intune record
    $targets = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    $i = 0
    foreach ($m in $deviceMembers) {
        if ($Limit -gt 0 -and $targets.Count -ge $Limit) { break }
        $i++
        $host_ = $m.displayName
        $aadId = $m.deviceId
        Write-Host "[$i/$($deviceMembers.Count)] Resolving $host_"
        if (-not (Test-GuidText $aadId)) { [void]$skipped.Add("$host_ : no valid Entra device id"); continue }
        try {
            $mf = [uri]::EscapeDataString("azureADDeviceId eq '$aadId'")
            $r = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$mf"
            $md = $r.value | Select-Object -First 1
        } catch {
            [void]$skipped.Add("$host_ : could not read the Intune record ($($_.Exception.Message))"); continue
        }
        if (-not $md) { [void]$skipped.Add("$host_ : no Intune managed device record"); continue }
        if ($md.operatingSystem -and $md.operatingSystem -ne 'Windows') { [void]$skipped.Add("$host_ : not Windows ($($md.operatingSystem)); Run remediation supports Windows only"); continue }
        $sync = $null
        try { if ($md.lastSyncDateTime) { $sync = [datetime]$md.lastSyncDateTime } } catch { $sync = $null }
        if ($MaxDaysSinceSync -gt 0) {
            if (-not $sync) { [void]$skipped.Add("$host_ : no last check-in time"); continue }
            if ($sync.ToUniversalTime() -lt (Get-Date).ToUniversalTime().AddDays(-$MaxDaysSinceSync)) {
                [void]$skipped.Add("$host_ : last check-in $($sync.ToString('yyyy-MM-dd')) is older than $MaxDaysSinceSync day(s)"); continue
            }
        }
        [void]$targets.Add([pscustomobject]@{ Hostname = $host_; ManagedDeviceId = $md.id; LastSyncDateTime = $sync })
    }

    Write-Host ""
    Write-Host "================ SUMMARY ================"
    Write-Host "Group              : $groupLabel"
    Write-Host "Device members     : $($deviceMembers.Count)"
    Write-Host "Remediation        : $scriptLabel"
    Write-Host "Will target        : $($targets.Count) device(s)$(if ($Limit -gt 0) { " (limited to the first $Limit)" })"
    Write-Host "Skipped            : $($skipped.Count)"
    foreach ($s in $skipped) { Write-Host "  - $s" -ForegroundColor Yellow }
    Write-Host "========================================="

    if ($targets.Count -eq 0) { Stop-Run 'No eligible devices to target.' }

    if (-not $Execute) {
        Write-Host ""
        Write-Host "DRY RUN. No -Execute switch was passed, so nothing was triggered. Devices that WOULD be targeted:"
        foreach ($t in $targets) {
            $when = 'unknown'
            if ($t.LastSyncDateTime) { $when = $t.LastSyncDateTime.ToString('yyyy-MM-dd HH:mm') }
            Write-Host ("  - {0}   (last check-in {1})" -f $t.Hostname, $when)
        }
        Write-Host ""
        Write-Host "Next: re-run with -Execute -Limit 5 as a test batch, check Device status in the admin center, then run the full group."
        exit 0
    }

    # ------------------------------------------------------------ 6. confirm, then trigger
    Write-Host ""
    Write-Host "About to trigger '$scriptLabel' on $($targets.Count) device(s). The remediation script will run on each one." -ForegroundColor Yellow
    $answer = Read-Host "Type YES to confirm"
    if ($answer -cne 'YES') { Write-Host 'Aborted. Nothing was triggered.'; exit 0 }

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ("RemediationRun-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date)) }
    $body = (@{ scriptPolicyId = $scriptIdResolved } | ConvertTo-Json -Compress)
    $results = New-Object System.Collections.ArrayList
    $n = 0
    foreach ($t in $targets) {
        $n++
        Write-Host "[$n/$($targets.Count)] Sending to $($t.Hostname)..."
        $status = 'Accepted'; $detail = ''
        try {
            [void](Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($t.ManagedDeviceId)/initiateOnDemandProactiveRemediation" -Body $body)
            Write-Host '  accepted by Graph (204)'
        } catch {
            $status = 'Failed'; $detail = $_.Exception.Message
            Write-Warning "  FAILED: $detail"
        }
        [void]$results.Add([pscustomobject]@{
            Hostname = $t.Hostname; ManagedDeviceId = $t.ManagedDeviceId
            LastSyncDateTime = $t.LastSyncDateTime; Status = $status; Detail = $detail
            SentUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        })
        Start-Sleep -Milliseconds 300
    }

    $results | Export-Csv -Path $OutputPath -NoTypeInformation
    $ok = @($results | Where-Object { $_.Status -eq 'Accepted' }).Count
    $bad = $results.Count - $ok
    Write-Host ""
    Write-Host "DONE. Accepted by Graph: $ok. Failed: $bad. Results: $OutputPath"
    Write-Host "Accepted is NOT proof the script ran. Offline devices do not receive the action. Check Devices > Scripts and remediations > '$scriptLabel' > Device status."
    if ($bad -gt 0) { exit 2 }
    exit 0
} finally {
    try { Disconnect-MgGraph | Out-Null } catch { }
}
