<#
.SYNOPSIS
    Finds Entra ID users who rely on SMS/voice MFA only and have no passkey or Authenticator app registered.

.DESCRIPTION
    Queries Microsoft Graph to identify users at risk of being locked out when Microsoft
    removes SMS and voice call authentication on 1 February 2027. Exports results to CSV.

    READ-ONLY — this script does not modify any users or settings.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/entra-passkeys-default-authentication-2026.html
    Requires:    Microsoft.Graph PowerShell module
    Permissions: UserAuthenticationMethod.Read.All (delegated)
    Version:     1.0
    Date:        2026-07-14

.EXAMPLE
    .\Get-SMSOnlyUsers.ps1
    Connects to Microsoft Graph and exports SMS-only users to C:\Temp\SMS-Only-Users.csv

.EXAMPLE
    .\Get-SMSOnlyUsers.ps1 -OutputPath "C:\Reports\sms-users.csv"
    Exports to a custom path.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\Temp\SMS-Only-Users-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
)

# ── Check module ──────────────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
$tenantId   = 'YOUR-TENANT-ID'        # e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$clientId   = 'YOUR-APP-CLIENT-ID'    # App registration client ID from Entra
$thumbprint = 'YOUR-CERT-THUMBPRINT'  # Certificate thumbprint from app registration
Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint -NoWelcome

# ── Get members of test group ─────────────────────────────────────────────────
$groupName = 'YOUR-GROUP-NAME'  # Set to your Entra group name, or leave blank to scan all users
Write-Host "Looking up group: $groupName" -ForegroundColor Cyan

$groupSearch = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$groupName'&`$select=id,displayName" -Method GET
if (-not $groupSearch.value -or $groupSearch.value.Count -eq 0) {
    Write-Host "ERROR: Group '$groupName' not found. Check the name and try again." -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit
}
$groupId = $groupSearch.value[0].id
Write-Host "Found group: $groupName (ID: $groupId)" -ForegroundColor Green

Write-Host "Fetching group members..." -ForegroundColor Cyan
$users = [System.Collections.Generic.List[PSObject]]::new()
$uri   = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,userPrincipalName,accountEnabled&`$top=999"

do {
    $page = Invoke-MgGraphRequest -Uri $uri -Method GET
    foreach ($u in $page.value) {
        if ($u.'@odata.type' -eq '#microsoft.graph.user' -and $u.accountEnabled) {
            $users.Add([PSCustomObject]$u)
        }
    }
    $uri = $page.'@odata.nextLink'
} while ($uri)

Write-Host "Found $($users.Count) enabled users in group. Checking auth methods..." -ForegroundColor Cyan

# ── Check each user's auth methods ───────────────────────────────────────────
$results = [System.Collections.Generic.List[PSObject]]::new()
$i = 0

foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Checking authentication methods" `
                   -Status "$i of $($users.Count): $($user.userPrincipalName)" `
                   -PercentComplete (($i / $users.Count) * 100)

    try {
        $resp  = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods" -Method GET
        $types = $resp.value.'@odata.type'

        $hasSMS     = $types -contains '#microsoft.graph.phoneAuthenticationMethod'
        $hasPasskey = $types -contains '#microsoft.graph.fido2AuthenticationMethod'
        $hasAuth    = $types -contains '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
        $hasWHfB    = $types -contains '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
        $hasTOTP    = $types -contains '#microsoft.graph.softwareOathAuthenticationMethod'

        $atRisk = $hasSMS -and -not $hasPasskey -and -not $hasAuth -and -not $hasWHfB

        if ($atRisk) {
            $results.Add([PSCustomObject]@{
                DisplayName      = $user.displayName
                UPN              = $user.userPrincipalName
                HasSMS_Voice     = $hasSMS
                HasPasskey_FIDO2 = $hasPasskey
                HasAuthenticator = $hasAuth
                HasWHfB          = $hasWHfB
                HasTOTP          = $hasTOTP
                RiskLevel        = 'HIGH - Will lose MFA access on 1 Feb 2027'
            })
        }
    }
    catch {
        Write-Warning "Could not get methods for $($user.userPrincipalName): $_"
    }
}

Write-Progress -Activity "Checking authentication methods" -Completed

# ── Output results ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " RESULTS SUMMARY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Total enabled users checked : $($users.Count)" -ForegroundColor White
Write-Host " At-risk users (SMS only)    : $($results.Count)" -ForegroundColor $(if ($results.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

if ($results.Count -gt 0) {
    Write-Host "At-risk users:" -ForegroundColor Red
    $results | Format-Table DisplayName, UPN, RiskLevel -AutoSize

    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $OutputPath" -ForegroundColor Yellow
    Write-Host "`nNext step: Use these UPNs to target your Entra ID registration campaign." -ForegroundColor Cyan
} else {
    Write-Host "No at-risk users found. All users have a passkey, Authenticator, or WHfB registered." -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null
Write-Host "Done." -ForegroundColor Green
