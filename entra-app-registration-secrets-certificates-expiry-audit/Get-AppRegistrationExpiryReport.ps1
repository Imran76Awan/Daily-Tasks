<#
.SYNOPSIS
    Audits every Entra ID app registration in the tenant for expiring or expired
    client secrets and certificates.

.DESCRIPTION
    Connects to Microsoft Graph and calls Get-MgApplication -All to pull every app
    registration in the tenant. For each application it inspects the
    PasswordCredentials array (client secrets) and the KeyCredentials array
    (certificates), and for every single credential it compares EndDateTime against
    the current date.

    A single app registration can hold multiple credentials at once, and it is
    common for several expired credentials to sit next to one still-valid one. This
    script checks every credential individually rather than just checking whether
    an app "has a secret" - a healthy-looking app can still be carrying dead
    credentials that nobody ever cleaned up.

    Each credential is classified into one of three buckets:
      - Expired  : EndDateTime is in the past. Red output.
      - Expiring : EndDateTime falls within -WarningDays of today (default 30). Amber output.
      - Healthy  : EndDateTime is more than -WarningDays away. Green output.

    The script writes colour-coded output to the console and a summary count at the
    end. If -ExportCsv is supplied, the full per-credential results are also written
    to a timestamped CSV file in the current directory.

    This script is READ-ONLY. It only requires Application.Read.All and it never
    creates, rotates, or deletes a credential. It reports what it finds; you decide
    what to do about it.

.PARAMETER TenantId
    Tenant ID (GUID or verified domain) to use for app-only certificate
    authentication. Required together with -ClientId and -CertificateThumbprint. If
    omitted, the script falls back to interactive device-code sign-in.

.PARAMETER ClientId
    Application (client) ID of the app registration used for app-only certificate
    authentication. Required together with -TenantId and -CertificateThumbprint.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (in the local certificate store) used for app-only
    authentication. Required together with -TenantId and -ClientId.

.PARAMETER WarningDays
    Number of days from today within which a credential is classified as
    "Expiring" rather than "Healthy". Default is 30.

.PARAMETER ExportCsv
    Switch. When supplied, writes the full per-credential result set to a CSV file
    named AppRegistrationExpiryReport-yyyyMMdd-HHmmss.csv in the current directory.

.EXAMPLE
    .\Get-AppRegistrationExpiryReport.ps1

    Runs interactively. Prompts for device-code sign-in with the
    Application.Read.All scope, then reports every credential expiring within the
    next 30 days.

.EXAMPLE
    .\Get-AppRegistrationExpiryReport.ps1 -WarningDays 60 -ExportCsv

    Runs interactively with a wider 60-day warning window and exports the full
    result set to CSV.

.EXAMPLE
    .\Get-AppRegistrationExpiryReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD" -WarningDays 30 -ExportCsv

    Runs unattended using app-only certificate authentication, suitable for a
    scheduled task or an Azure Automation runbook.

.NOTES
    Author  : Imran Awan
    Blog    : https://endpointweekly.com/blog/entra-app-registration-secrets-certificates-expiry-audit.html
    Module  : Microsoft.Graph.Applications
    Scope   : Application.Read.All (read-only, no writes performed by this script)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [int]$WarningDays = 30,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

# --- Always connect fresh. Never trust a stale cached Get-MgContext, because a
#     leftover session from a different tenant or a different set of scopes will
#     silently return the wrong (or empty) results without any error. ---
try {
    if (Get-MgContext) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
catch {
    # No existing context to disconnect - that is fine, carry on.
}

Write-Section "Connecting to Microsoft Graph"

try {
    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Write-Host "[INFO] Using app-only certificate authentication (TenantId/ClientId/CertificateThumbprint supplied)." -ForegroundColor Yellow
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    }
    else {
        Write-Host "[INFO] No app-only credentials supplied - falling back to interactive device-code sign-in." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "Application.Read.All" -UseDeviceCode -NoWelcome
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

$context = Get-MgContext
if (-not $context) {
    Write-Error "Microsoft Graph connection did not produce a valid context. Aborting - refusing to report a possibly-empty result as if it were a clean tenant."
    exit 1
}

Write-Host "[INFO] Connected. Tenant: $($context.TenantId)  Account: $($context.Account)" -ForegroundColor Green

# --- Pull every app registration in the tenant. ---
Write-Section "Retrieving app registrations"

try {
    $apps = Get-MgApplication -All -Property "Id,AppId,DisplayName,PasswordCredentials,KeyCredentials"
}
catch {
    Write-Error "Get-MgApplication failed: $($_.Exception.Message). Aborting - a failed query must never be reported as '0 app registrations found', which would be indistinguishable from a genuinely empty tenant."
    exit 1
}

if ($null -eq $apps) {
    Write-Error "Get-MgApplication returned null instead of an array. Aborting rather than silently reporting zero results."
    exit 1
}

Write-Host "[INFO] Found $($apps.Count) app registration(s) in the tenant." -ForegroundColor Green

# --- Walk every credential on every app and classify it. ---
Write-Section "Evaluating credentials"

$now = Get-Date
$results = New-Object System.Collections.Generic.List[Object]

foreach ($app in $apps) {

    foreach ($secret in $app.PasswordCredentials) {
        $daysToExpiry = [math]::Round(($secret.EndDateTime - $now).TotalDays)

        if ($daysToExpiry -lt 0) {
            $status = "Expired"
        }
        elseif ($daysToExpiry -le $WarningDays) {
            $status = "Expiring"
        }
        else {
            $status = "Healthy"
        }

        $results.Add([PSCustomObject]@{
            AppDisplayName = $app.DisplayName
            AppId          = $app.AppId
            ObjectId       = $app.Id
            CredentialType = "Secret"
            CredentialName = $secret.DisplayName
            KeyId          = $secret.KeyId
            StartDateTime  = $secret.StartDateTime
            EndDateTime    = $secret.EndDateTime
            DaysToExpiry   = $daysToExpiry
            Status         = $status
        })
    }

    foreach ($cert in $app.KeyCredentials) {
        $daysToExpiry = [math]::Round(($cert.EndDateTime - $now).TotalDays)

        if ($daysToExpiry -lt 0) {
            $status = "Expired"
        }
        elseif ($daysToExpiry -le $WarningDays) {
            $status = "Expiring"
        }
        else {
            $status = "Healthy"
        }

        $results.Add([PSCustomObject]@{
            AppDisplayName = $app.DisplayName
            AppId          = $app.AppId
            ObjectId       = $app.Id
            CredentialType = "Certificate"
            CredentialName = $cert.DisplayName
            KeyId          = $cert.KeyId
            StartDateTime  = $cert.StartDateTime
            EndDateTime    = $cert.EndDateTime
            DaysToExpiry   = $daysToExpiry
            Status         = $status
        })
    }
}

# --- Print colour-coded findings, worst first. ---
Write-Section "Findings"

$sorted = $results | Sort-Object -Property @{Expression = "DaysToExpiry"; Ascending = $true}

if ($sorted.Count -eq 0) {
    Write-Host "[INFO] No client secrets or certificates found on any app registration in this tenant." -ForegroundColor Yellow
}
else {
    foreach ($row in $sorted) {
        $label = "[{0,-8}] {1,-14} {2,-40} {3,-24} ends {4}  ({5} day(s))" -f `
            $row.Status.ToUpper(), $row.CredentialType, $row.AppDisplayName, ($row.CredentialName -replace '^$', '(unnamed)'), $row.EndDateTime, $row.DaysToExpiry

        switch ($row.Status) {
            "Expired"  { Write-Host $label -ForegroundColor Red }
            "Expiring" { Write-Host $label -ForegroundColor Yellow }
            "Healthy"  { Write-Host $label -ForegroundColor Green }
        }
    }
}

# --- Summary. ---
Write-Section "Summary"

$expiredCount  = ($results | Where-Object { $_.Status -eq "Expired" }).Count
$expiringCount = ($results | Where-Object { $_.Status -eq "Expiring" }).Count
$healthyCount  = ($results | Where-Object { $_.Status -eq "Healthy" }).Count

Write-Host "Total app registrations scanned : $($apps.Count)"
Write-Host "Total credentials evaluated      : $($results.Count)"
Write-Host "Expired credentials              : $expiredCount" -ForegroundColor Red
Write-Host "Expiring within $WarningDays day(s)         : $expiringCount" -ForegroundColor Yellow
Write-Host "Healthy credentials               : $healthyCount" -ForegroundColor Green

if ($ExportCsv) {
    $csvPath = Join-Path -Path (Get-Location) -ChildPath ("AppRegistrationExpiryReport-{0}.csv" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    try {
        $results | Sort-Object -Property DaysToExpiry | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "[INFO] Full results exported to: $csvPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV to $csvPath : $($_.Exception.Message)"
        exit 1
    }
}

Write-Host ""
Write-Host "[INFO] Audit complete." -ForegroundColor Green
