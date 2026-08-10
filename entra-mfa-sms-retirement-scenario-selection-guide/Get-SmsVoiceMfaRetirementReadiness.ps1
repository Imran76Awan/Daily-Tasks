<#
.SYNOPSIS
    Reports which users in a Microsoft Entra ID tenant are still relying on SMS or
    Voice as their only registered authentication method, ahead of Microsoft's
    retirement of SMS/Voice as MFA methods on 1 February 2027.

.DESCRIPTION
    Read-only script. Calls Microsoft Graph (GET requests only) to enumerate every
    user's registered authentication methods and flags:
      - Users whose ONLY registered method is SMS or Voice (will lose MFA access
        outright once retirement completes, unless a customer-managed telecom
        provider is configured).
      - Users with NO registered authentication method at all.
    Exports the full result set to a CSV and prints a summary to the console.

    This script does not change any configuration, does not register or remove
    any authentication method, and does not modify any policy. It only reads.

.NOTES
    Author: EndpointWeekly
    Blog:   https://endpointweekly.com/blog/entra-mfa-sms-retirement-scenario-selection-guide.html
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
              Microsoft.Graph.Identity.SignIns PowerShell modules.
    Required Graph permission: UserAuthenticationMethod.Read.All (application or
    delegated). No write permissions are requested or used.

.EXAMPLE
    .\Get-SmsVoiceMfaRetirementReadiness.ps1
    Runs an interactive device-code sign-in and exports the report to the current
    directory.

.EXAMPLE
    .\Get-SmsVoiceMfaRetirementReadiness.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    Runs unattended using app-only authentication with a certificate, for use in a
    scheduled task or CI pipeline.

.EXAMPLE
    .\Get-SmsVoiceMfaRetirementReadiness.ps1 -CsvPath "C:\Reports\SmsVoiceReadiness.csv"
    Runs interactively and writes the CSV to a specific path instead of the current
    directory.
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
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = (Join-Path -Path (Get-Location) -ChildPath ("SmsVoiceReadiness_{0}.csv" -f (Get-Date -Format "yyyy-MM-dd")))
)

$script:hadError = $false

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "--- $Text ---" -ForegroundColor Cyan
}

function Connect-ToGraph {
    $requiredScopes = @("UserAuthenticationMethod.Read.All")

    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Write-Host "Connecting with app-only certificate authentication..." -ForegroundColor Yellow
        try {
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
        }
        catch {
            Write-Error "App-only certificate sign-in failed: $($_.Exception.Message)"
            $script:hadError = $true
            return $false
        }
        return $true
    }

    Write-Host "Connecting with interactive/device-code authentication (delegated)..." -ForegroundColor Yellow
    try {
        if ($UseDeviceCode) {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Standard interactive sign-in failed, retrying with device code: $($_.Exception.Message)"
        try {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
        }
        catch {
            Write-Error "Device-code sign-in also failed: $($_.Exception.Message)"
            $script:hadError = $true
            return $false
        }
    }
    return $true
}

function Get-UserMethodSummary {
    param([Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser]$User)

    $result = [ordered]@{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        Methods           = @()
        AtRisk            = $false
        NoMethods         = $false
    }

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read authentication methods for $($User.UserPrincipalName): $($_.Exception.Message)"
        $script:hadError = $true
        $result.Methods = @("ERROR-READING-METHODS")
        return [pscustomobject]$result
    }

    $methodNames = @()
    foreach ($method in $methods) {
        $typeName = $method.AdditionalProperties["@odata.type"]
        if (-not $typeName) { $typeName = $method.GetType().Name }
        $shortName = $typeName -replace ".*\.", "" -replace "AuthenticationMethod$", ""
        if ($shortName -notin @("Password")) {
            $methodNames += $shortName
        }
    }

    $result.Methods = $methodNames

    if ($methodNames.Count -eq 0) {
        $result.NoMethods = $true
    }
    elseif (($methodNames | Where-Object { $_ -in @("PhoneSms", "PhoneVoice", "Phone") }).Count -eq $methodNames.Count) {
        $result.AtRisk = $true
    }

    return [pscustomobject]$result
}

function Main {
    Write-Section "SMS/Voice MFA Retirement Readiness"

    $connected = Connect-ToGraph
    if (-not $connected) {
        Write-Error "Could not establish a Microsoft Graph connection. Exiting."
        exit 1
    }

    $users = @()
    try {
        $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName,AccountEnabled" -ErrorAction Stop |
            Where-Object { $_.AccountEnabled -eq $true }
    }
    catch {
        Write-Error "Failed to enumerate users: $($_.Exception.Message)"
        $script:hadError = $true
        exit 1
    }

    if ($users.Count -eq 0) {
        Write-Warning "No enabled users returned. Nothing to report."
        exit 1
    }

    $results = @()
    $processed = 0
    foreach ($user in $users) {
        $results += Get-UserMethodSummary -User $user
        $processed++
        if ($processed % 25 -eq 0) {
            Write-Host "  ...scanned $processed of $($users.Count) users" -ForegroundColor DarkGray
        }
    }

    $atRisk    = $results | Where-Object { $_.AtRisk -eq $true }
    $noMethods = $results | Where-Object { $_.NoMethods -eq $true }
    $healthy   = $results | Where-Object { $_.AtRisk -eq $false -and $_.NoMethods -eq $false }

    Write-Host ("Total users scanned      : {0}" -f $results.Count) -ForegroundColor Green
    Write-Host ("Passkey or WHfB or other registered : {0}" -f $healthy.Count) -ForegroundColor Green
    Write-Host ("SMS/Voice ONLY (at risk)  : {0}" -f $atRisk.Count) -ForegroundColor Red
    Write-Host ("No MFA method registered  : {0}" -f $noMethods.Count) -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------"

    foreach ($item in $atRisk) {
        Write-Host ("{0}  - methods: [{1}]" -f $item.UserPrincipalName, ($item.Methods -join ", ")) -ForegroundColor Red
    }
    foreach ($item in $noMethods) {
        Write-Host ("{0}  - methods: [] (never registered)" -f $item.UserPrincipalName) -ForegroundColor Yellow
    }

    Write-Host "------------------------------------------------------------"

    try {
        $results |
            Select-Object UserPrincipalName, DisplayName, @{N = "Methods"; E = { $_.Methods -join ";" } }, AtRisk, NoMethods |
            Export-Csv -Path $CsvPath -NoTypeInformation -ErrorAction Stop
        Write-Host ("Report exported to: {0}" -f $CsvPath) -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write CSV to $CsvPath : $($_.Exception.Message)"
        $script:hadError = $true
    }

    if ($script:hadError) {
        exit 1
    }
    exit 0
}

Main
