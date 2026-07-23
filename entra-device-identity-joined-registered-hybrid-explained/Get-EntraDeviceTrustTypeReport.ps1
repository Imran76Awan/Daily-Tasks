<#
.SYNOPSIS
    Reports the Microsoft Entra device trust type distribution across the tenant's device inventory.

.DESCRIPTION
    Connects to Microsoft Graph (read-only) and pulls every device object registered in Microsoft
    Entra ID using Get-MgDevice. Groups the results by the "trustType" property to show how many
    devices are:

        AzureAd    - Microsoft Entra joined (cloud-only joined devices)
        ServerAd   - Microsoft Entra hybrid joined (on-premises AD joined + synced to Entra ID)
        Workplace  - Microsoft Entra registered (bring-your-own / personal devices)
        (blank)    - trustType has never been set (rare; can occur on some device objects
                      that predate current registration flows, or objects created directly via
                      Graph without going through a registration flow). Flagged separately rather
                      than silently dropped or guessed at.

    This script makes no changes to any device, group, or directory object. It only reads data.

    Companion script for the EndpointWeekly post:
    https://endpointweekly.com/blog/entra-device-identity-joined-registered-hybrid-explained.html

.PARAMETER TenantId
    Optional. The Entra tenant ID (GUID) or verified domain to connect to. If omitted, Connect-MgGraph
    uses the default tenant for the signed-in identity.

.PARAMETER ExportCsv
    Optional. Full path to a CSV file. If supplied, the full per-device breakdown is also exported
    to this path in addition to being printed to the console.

.EXAMPLE
    .\Get-EntraDeviceTrustTypeReport.ps1

    Connects interactively (delegated) and prints a trust-type summary plus per-device table to
    the console.

.EXAMPLE
    .\Get-EntraDeviceTrustTypeReport.ps1 -TenantId "contoso.onmicrosoft.com" -ExportCsv "C:\Reports\trusttype.csv"

    Connects to a specific tenant and also exports the full per-device breakdown to CSV.

.NOTES
    Author        : EndpointWeekly / Imran Awan
    Blog post     : https://endpointweekly.com/blog/entra-device-identity-joined-registered-hybrid-explained.html
    Requires      : Microsoft.Graph.Identity.DirectoryManagement module (Get-MgDevice)
    Permissions   : Device.Read.All (delegated or application)
    Read-only     : Yes. This script never calls Update-MgDevice, Remove-MgDevice, or any write cmdlet.
    Trust values  : Verified against Microsoft Graph v1.0 "device" resource documentation
                    (trustType possible values: Workplace, AzureAd, ServerAd). See references in the
                    blog post before relying on this in a scripted pipeline against a new Graph API version.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement)) {
        throw "Microsoft.Graph.Identity.DirectoryManagement module is not installed. Run: Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser"
    }

    Write-Section "Connecting to Microsoft Graph"

    $connectParams = @{
        Scopes = @('Device.Read.All')
        NoWelcome = $true
    }
    if ($TenantId) {
        $connectParams['TenantId'] = $TenantId
    }

    Connect-MgGraph @connectParams

    $context = Get-MgContext
    if (-not $context) {
        throw "Connect-MgGraph did not return a valid context. Aborting - cannot verify Graph connection."
    }
    Write-Host "Connected to tenant: $($context.TenantId) as $($context.Account)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Section "Retrieving device inventory (Get-MgDevice -All)"

    # -All pages through the full result set. -Property limits the payload to what we actually need.
    $devices = Get-MgDevice -All -Property Id, DisplayName, TrustType, OperatingSystem, OperatingSystemVersion, AccountEnabled, ApproximateLastSignInDateTime

    if (-not $devices) {
        Write-Warning "Get-MgDevice returned zero device objects. Either the tenant has no registered devices, or the account used lacks Device.Read.All. Nothing to report."
        exit 0
    }

    $totalCount = $devices.Count
    Write-Host "Retrieved $totalCount device object(s) from Microsoft Entra ID." -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve devices from Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Section "Trust type distribution"

    # Normalise null/empty trustType into an explicit label instead of silently grouping it away.
    $grouped = $devices | Group-Object -Property {
        if ([string]::IsNullOrWhiteSpace($_.TrustType)) { '(blank / never set)' } else { $_.TrustType }
    } | Sort-Object Count -Descending

    $summary = foreach ($group in $grouped) {
        [PSCustomObject]@{
            TrustType  = $group.Name
            Meaning    = switch ($group.Name) {
                'AzureAd'              { 'Microsoft Entra joined' }
                'ServerAd'             { 'Microsoft Entra hybrid joined' }
                'Workplace'            { 'Microsoft Entra registered (BYOD)' }
                '(blank / never set)'  { 'FLAG - trustType not populated, verify manually' }
                default                { "FLAG - unrecognised value '$($group.Name)', verify against current Graph docs" }
            }
            DeviceCount = $group.Count
            PercentOfTotal = [math]::Round(($group.Count / $totalCount) * 100, 1)
        }
    }

    $summary | Format-Table -AutoSize

    $unrecognised = $summary | Where-Object { $_.Meaning -like 'FLAG*' }
    if ($unrecognised) {
        Write-Warning "One or more trustType values did not match the three documented values (Workplace, AzureAd, ServerAd). Review these devices manually before drawing conclusions."
    }
}
catch {
    Write-Error "Failed to compute trust type distribution: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Section "Per-device breakdown"

    $trustTypeExpr = @{
        Name = 'TrustType'
        Expression = { if ([string]::IsNullOrWhiteSpace($_.TrustType)) { '(blank)' } else { $_.TrustType } }
    }

    $detail = $devices |
        Select-Object -Property DisplayName, $trustTypeExpr, OperatingSystem, OperatingSystemVersion, AccountEnabled, ApproximateLastSignInDateTime |
        Sort-Object -Property TrustType, DisplayName

    $detail | Format-Table -AutoSize

    if ($ExportCsv) {
        $detail | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Per-device breakdown exported to: $ExportCsv" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to build or export the per-device breakdown: $($_.Exception.Message)"
    exit 1
}

Write-Section "Done"
Write-Host "Total devices: $totalCount" -ForegroundColor Green
Write-Host "This script made no changes. It only read device objects via Get-MgDevice." -ForegroundColor Green
