<#
.SYNOPSIS
    Audits Microsoft Entra Cloud Sync job health across a tenant using Microsoft Graph.

.DESCRIPTION
    Get-CloudSyncHealthReport.ps1 enumerates every service principal in the tenant and checks
    whether it has an active Microsoft Entra Cloud Sync (Graph "synchronization") configuration.
    For every service principal that does, it reads the most recent job execution status via
    Get-MgServicePrincipalSynchronizationJob and classifies the job as Healthy or Failing based on:

      - Status.LastExecution.State (expected value on success: "Succeeded")
      - Status.CountSuccessiveCompleteFailures (a rising number means the job has failed several
        complete cycles in a row with nobody intervening)
      - Per-step failure counts inside Status.Steps (a job can show CountSuccessiveCompleteFailures
        of 0 while specific objects are still failing individually inside an otherwise "successful" run)

    This script deliberately does NOT assume a specific display name pattern for the Cloud Sync
    service principal (naming can vary by tenant and has changed historically). Instead it performs
    a generic enumeration: ask every service principal whether it has any synchronization jobs at
    all, and report on every one that does. Service principals with no synchronization configuration
    are silently skipped -- that is expected and is not treated as an error.

    Authentication: the script first attempts app-only certificate-based authentication
    (Connect-MgGraph -ClientId -TenantId -CertificateThumbprint). If certificate parameters are not
    supplied, it falls back to interactive device-code authentication (Connect-MgGraph -UseDeviceCode).
    The script always connects fresh at the start of every run -- it never silently reuses a stale
    cached Graph context from a previous session.

    Required Microsoft Graph permission: Synchronization.Read.All (application or delegated). This is
    a read-only scope. The script never triggers, restarts, resumes, or modifies a synchronization job
    -- it only reads and reports job status.

    Failure handling: any Microsoft Graph error that is not simply "this service principal has no
    synchronization configuration" (authentication failure, permission denial, throttling, timeout,
    etc.) is written to the error stream and causes the script to exit with code 1. The script never
    reports "0 failing jobs / all healthy" when the real story is "the script could not query Graph
    successfully" -- an empty or incomplete result due to a Graph error is always treated as a failed
    run, not a healthy one.

.PARAMETER TenantId
    The Entra ID tenant ID (GUID) or verified domain name to connect to.

.PARAMETER ClientId
    The application (client) ID of the app registration used for app-only certificate authentication.
    Required together with -CertificateThumbprint for non-interactive/scheduled use. If omitted, the
    script falls back to interactive device-code sign-in.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate (installed in the local certificate store) associated with the
    app registration specified by -ClientId. Required together with -ClientId for app-only auth.

.PARAMETER ExportCsv
    Switch. When present, writes a timestamped CSV report of every synchronization job found
    (healthy and failing) to the current working directory, in addition to the console output.

.PARAMETER CsvPath
    Optional. Overrides the default CSV output location when -ExportCsv is used. Defaults to
    ".\CloudSyncHealthReport_<yyyyMMdd-HHmmss>.csv" in the current directory.

.EXAMPLE
    .\Get-CloudSyncHealthReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "AB12CD34EF56..."

    Runs the audit using app-only certificate authentication -- suitable for a scheduled task or
    Azure Automation runbook with no user interaction.

.EXAMPLE
    .\Get-CloudSyncHealthReport.ps1 -TenantId "contoso.onmicrosoft.com" -ExportCsv

    Runs the audit interactively (device-code sign-in, since no certificate parameters were supplied)
    and additionally writes a timestamped CSV report to the current directory.

.NOTES
    Author        : Imran Awan
    Blog post     : https://endpointweekly.com/blog/entra-cloud-sync-health-error-audit.html
    Requires      : Microsoft.Graph.Applications, Microsoft.Graph.Authentication PowerShell modules
    Requires      : Synchronization.Read.All (Microsoft Graph)
    Scope         : Microsoft Entra Cloud Sync only. This script does NOT audit classic Microsoft
                    Entra Connect Sync (the on-premises full sync engine), which does not expose an
                    equivalent Graph read surface for job health.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$script:hadGraphError = $false

function Write-Section {
    param([string]$Text)
    Write-Host ('=' * 64) -ForegroundColor DarkGray
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkGray
}

function Connect-CloudSyncGraph {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint
    )

    # Always start clean -- never trust a leftover context from a previous script run or session.
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # No existing session to disconnect -- not an error.
    }

    $requiredScopes = @('Synchronization.Read.All')

    try {
        if ($ClientId -and $CertificateThumbprint) {
            Write-Host "Connecting to Microsoft Graph (app-only certificate auth)..." -ForegroundColor Yellow
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
        } else {
            Write-Host "No certificate credentials supplied -- falling back to interactive device-code sign-in..." -ForegroundColor Yellow
            Connect-MgGraph -TenantId $TenantId -Scopes $requiredScopes -UseDeviceCode -NoWelcome
        }
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 1
    }

    $context = Get-MgContext
    if (-not $context) {
        Write-Error "Microsoft Graph connection could not be established. Aborting -- refusing to report an empty result as healthy."
        exit 1
    }

    Write-Host "Connected. Tenant: $($context.TenantId)" -ForegroundColor Green
}

function Get-CloudSyncJobReport {
    <#
        Enumerates all service principals and returns one report object per synchronization job
        found. Service principals with no synchronization configuration are skipped silently.
        Any other Graph error is recorded and flips $script:hadGraphError to $true.
    #>

    $report = [System.Collections.Generic.List[object]]::new()

    Write-Host "Enumerating service principals with active synchronization jobs..." -ForegroundColor Yellow

    $allServicePrincipals = @()
    try {
        $allServicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
    } catch {
        Write-Error "Failed to enumerate service principals: $($_.Exception.Message)"
        $script:hadGraphError = $true
        return $report
    }

    Write-Host "  Service principals scanned            : $($allServicePrincipals.Count)"

    $spWithJobs = 0

    foreach ($sp in $allServicePrincipals) {

        $jobs = $null
        try {
            $jobs = Get-MgServicePrincipalSynchronizationJob -ServicePrincipalId $sp.Id -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'does not exist|not found|NotFound|404') {
                # No synchronization configuration on this service principal -- expected, not an error.
                continue
            } else {
                Write-Error "Graph call failed for service principal '$($sp.DisplayName)' ($($sp.Id)): $msg"
                $script:hadGraphError = $true
                continue
            }
        }

        if (-not $jobs) { continue }

        $spWithJobs++

        foreach ($job in $jobs) {

            $last = $job.Status.LastExecution
            $successiveFailures = $job.Status.CountSuccessiveCompleteFailures

            $stateValue = if ($last -and $last.State) { $last.State } else { 'Unknown' }
            $isFailing = ($stateValue -ne 'Succeeded') -or ($successiveFailures -gt 0)

            $objectsFailedThisRun = 0
            if ($job.Status.Steps) {
                foreach ($step in $job.Status.Steps) {
                    if ($step.SynchronizedEntryCountFailed) {
                        $objectsFailedThisRun += $step.SynchronizedEntryCountFailed
                    }
                }
            }

            $report.Add([PSCustomObject]@{
                ServicePrincipalDisplayName    = $sp.DisplayName
                ServicePrincipalId             = $sp.Id
                JobId                          = $job.Id
                State                          = $stateValue
                LastRunBegan                   = if ($last) { $last.TimeBegan } else { $null }
                LastRunEnded                   = if ($last) { $last.TimeEnded } else { $null }
                CountSuccessiveCompleteFailures = $successiveFailures
                ObjectsFailedThisRun           = $objectsFailedThisRun
                IsFailing                      = $isFailing
            })
        }
    }

    Write-Host "  Service principals with sync jobs     : $spWithJobs"

    return $report
}

function Write-CloudSyncReport {
    param([System.Collections.Generic.List[object]]$Report)

    Write-Host ""
    Write-Section "ENTRA CLOUD SYNC HEALTH REPORT - $(Get-Date -Format 'dd MMM yyyy HH:mm')"
    Write-Host "  Synchronization jobs found            : $($Report.Count)"
    Write-Host ""

    $healthyCount = 0
    $failingCount = 0

    foreach ($entry in $Report) {

        Write-Host "  ServicePrincipal   : $($entry.ServicePrincipalDisplayName)"
        Write-Host "  JobId              : $($entry.JobId)"

        if ($entry.IsFailing) {
            $failingCount++
            Write-Host "  State              : $($entry.State)" -ForegroundColor Red
            Write-Host "  LastRunBegan       : $($entry.LastRunBegan)"
            Write-Host "  LastRunEnded       : $($entry.LastRunEnded)"
            Write-Host "  CountSuccessiveCompleteFailures : $($entry.CountSuccessiveCompleteFailures)" -ForegroundColor Red
            Write-Host "  ObjectsFailedThisRun            : $($entry.ObjectsFailedThisRun)" -ForegroundColor Red
            Write-Host "  STATUS: FAILING -- investigate before this job's next cycle" -ForegroundColor Red
        } else {
            $healthyCount++
            Write-Host "  State              : $($entry.State)" -ForegroundColor Green
            Write-Host "  LastRunBegan       : $($entry.LastRunBegan)"
            Write-Host "  LastRunEnded       : $($entry.LastRunEnded)"
            Write-Host "  CountSuccessiveCompleteFailures : $($entry.CountSuccessiveCompleteFailures)" -ForegroundColor Green
            Write-Host "  ObjectsFailedThisRun            : $($entry.ObjectsFailedThisRun)" -ForegroundColor Green
            Write-Host "  STATUS: HEALTHY" -ForegroundColor Green
        }
        Write-Host ('-' * 64) -ForegroundColor DarkGray
    }

    Write-Section "SUMMARY"
    Write-Host "  Healthy jobs   : $healthyCount" -ForegroundColor Green
    Write-Host "  Failing jobs   : $failingCount" -ForegroundColor $(if ($failingCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host ('=' * 64) -ForegroundColor DarkGray

    if ($failingCount -gt 0) {
        Write-Host ""
        Write-Host "REMINDER: a job showing CountSuccessiveCompleteFailures = 0 is not automatically clean --" -ForegroundColor DarkYellow
        Write-Host "that counter resets on any single successful run even if specific objects are still" -ForegroundColor DarkYellow
        Write-Host "failing individually. Check ObjectsFailedThisRun and the Provisioning blade's per-object" -ForegroundColor DarkYellow
        Write-Host "error list for jobs at 0 consecutive failures too." -ForegroundColor DarkYellow
    }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

Connect-CloudSyncGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint

$report = Get-CloudSyncJobReport

if ($script:hadGraphError) {
    Write-Error "One or more Microsoft Graph calls failed during this run. The report above is incomplete and must not be treated as a clean bill of health. Exiting with code 1."
    exit 1
}

if ($report.Count -eq 0) {
    Write-Host ""
    Write-Host "No Microsoft Entra Cloud Sync (or other Graph-based provisioning) jobs were found on any" -ForegroundColor Yellow
    Write-Host "service principal in this tenant. If you expected at least one Cloud Sync configuration to" -ForegroundColor Yellow
    Write-Host "exist, verify the connected account/app registration has Synchronization.Read.All and that" -ForegroundColor Yellow
    Write-Host "you are connected to the correct tenant -- do not assume this means everything is healthy." -ForegroundColor Yellow
} else {
    Write-CloudSyncReport -Report $report
}

if ($ExportCsv) {
    if (-not $CsvPath) {
        $CsvPath = ".\CloudSyncHealthReport_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    }
    $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "CSV report written to: $CsvPath" -ForegroundColor Cyan
}

$failingJobCount = ($report | Where-Object { $_.IsFailing }).Count
if ($failingJobCount -gt 0) {
    exit 2
}

exit 0
