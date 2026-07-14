<#
.SYNOPSIS
    Reports passkey registration progress across your Entra ID tenant.

.DESCRIPTION
    Shows how many users have registered a passkey (FIDO2), Microsoft Authenticator,
    or Windows Hello for Business. Use this weekly to track your migration progress
    toward the 1 February 2027 SMS/voice deprecation deadline.

    READ-ONLY — this script does not modify any users or settings.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/entra-passkeys-default-authentication-2026.html
    Requires:    Microsoft.Graph PowerShell module
    Permissions: UserAuthenticationMethod.Read.All (delegated)
    Version:     1.0
    Date:        2026-07-14

.EXAMPLE
    .\Get-PasskeyRegistrationStatus.ps1
    Outputs a registration summary to the console.
#>

[CmdletBinding()]
param()

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

$total       = $users.Count
$fido2Count  = 0
$authCount   = 0
$whfbCount   = 0
$smsCount    = 0
$atRiskCount = 0
$i           = 0

foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Scanning auth methods" `
                   -Status "$i of $total : $($user.userPrincipalName)" `
                   -PercentComplete (($i / $total) * 100)

    try {
        $resp  = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods" -Method GET
        $types = $resp.value.'@odata.type'

        $hasFIDO2 = $types -contains '#microsoft.graph.fido2AuthenticationMethod'
        $hasAuth  = $types -contains '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
        $hasWHfB  = $types -contains '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
        $hasSMS   = $types -contains '#microsoft.graph.phoneAuthenticationMethod'

        if ($hasFIDO2) { $fido2Count++ }
        if ($hasAuth)  { $authCount++ }
        if ($hasWHfB)  { $whfbCount++ }
        if ($hasSMS)   { $smsCount++ }

        if ($hasSMS -and -not $hasFIDO2 -and -not $hasAuth -and -not $hasWHfB) {
            $atRiskCount++
        }
    }
    catch { }
}

Write-Progress -Activity "Scanning auth methods" -Completed

# ── Report ────────────────────────────────────────────────────────────────────
$passkeyOrStrong = [math]::Round((($fido2Count + $authCount + $whfbCount) / [math]::Max($total,1)) * 100, 1)
$atRiskPct       = [math]::Round(($atRiskCount / [math]::Max($total,1)) * 100, 1)

$date = Get-Date -Format 'dd MMM yyyy'
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  PASSKEY REGISTRATION STATUS - $date" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Total enabled users         : $total" -ForegroundColor White
Write-Host "  FIDO2 / Passkey registered  : $fido2Count" -ForegroundColor Cyan
Write-Host "  Microsoft Authenticator     : $authCount" -ForegroundColor Cyan
Write-Host "  Windows Hello for Business  : $whfbCount" -ForegroundColor Cyan
Write-Host "  SMS / Voice registered      : $smsCount" -ForegroundColor Yellow
Write-Host "  ----------------------------------------------" -ForegroundColor DarkGray
$atRiskStr   = $atRiskCount.ToString() + ' (' + $atRiskPct.ToString() + '%)'
$coverageStr = $passkeyOrStrong.ToString() + '%'
Write-Host "  At-risk (SMS only, no alt)  : $atRiskStr" -ForegroundColor $(if ($atRiskCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Phishing-resistant coverage : $coverageStr" -ForegroundColor $(if ($passkeyOrStrong -ge 90) { 'Green' } elseif ($passkeyOrStrong -ge 50) { 'Yellow' } else { 'Red' })
Write-Host "================================================" -ForegroundColor Green
Write-Host ""

if ($atRiskCount -gt 0) {
    Write-Host "ACTION: Run Get-SMSOnlyUsers.ps1 to get the full at-risk user list." -ForegroundColor Yellow
} else {
    Write-Host "All users have a phishing-resistant credential. Ready for 1 Feb 2027." -ForegroundColor Green
}

Disconnect-MgGraph | Out-Null
