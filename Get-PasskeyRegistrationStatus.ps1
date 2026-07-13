<#
.SYNOPSIS
    Reports FIDO2 passkey registration status for all Entra ID users.

.DESCRIPTION
    Queries Microsoft Graph to identify which users have registered a FIDO2 passkey,
    who is MFA-only, and who is still on password only.

    Output columns: UserPrincipalName | AuthMethod | Status | RegisteredOn

    As seen at:
    https://endpointweekly.com/blog/microsoft-authenticator-passkeys-entra-id-intune.html

.PARAMETER ExportCsv
    If specified, exports results to a CSV file in the same folder as the script.

.PARAMETER Top
    Limits output to the first N users (useful for testing). Default = all users.

.EXAMPLE
    .\Get-PasskeyRegistrationStatus.ps1

.EXAMPLE
    .\Get-PasskeyRegistrationStatus.ps1 -ExportCsv

.EXAMPLE
    .\Get-PasskeyRegistrationStatus.ps1 -Top 20

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/microsoft-authenticator-passkeys-entra-id-intune.html
    GitHub:      https://github.com/Imran76Awan/Windows-Patching-Scripts

    Required modules:
        Microsoft.Graph.Reports
        Microsoft.Graph.Identity.SignIns

    Required permissions (delegated):
        Reports.Read.All
        UserAuthenticationMethod.Read.All

    Install modules if missing:
        Install-Module Microsoft.Graph.Reports -Scope CurrentUser
        Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [int]$Top = 0
)

#region -- Module check ---------------------------------------------------------

$requiredModules = @('Microsoft.Graph.Reports', 'Microsoft.Graph.Identity.SignIns')

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Module '$mod' not found. Installing..." -ForegroundColor Yellow
        Install-Module $mod -Scope CurrentUser -Force -ErrorAction Stop
    }
    Import-Module $mod -ErrorAction Stop
}

#endregion

#region -- Connect --------------------------------------------------------------

Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

try {
    Connect-MgGraph `
        -Scopes 'Reports.Read.All', 'UserAuthenticationMethod.Read.All' `
        -NoWelcome `
        -ErrorAction Stop
} catch {
    Write-Host "ERROR: Failed to connect to Microsoft Graph." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor DarkRed
    exit 1
}

#endregion

#region -- Fetch registration details -------------------------------------------

Write-Host "`n# Querying Microsoft Graph - FIDO2 Authentication Methods API..." -ForegroundColor DarkGray

try {
    $registrations = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
} catch {
    Write-Host "ERROR: Could not retrieve authentication method registration details." -ForegroundColor Red
    Write-Host "Ensure the account has Reports.Read.All permission." -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor DarkRed
    Disconnect-MgGraph | Out-Null
    exit 1
}

if ($Top -gt 0) {
    $registrations = $registrations | Select-Object -First $Top
}

#endregion

#region -- Process each user ----------------------------------------------------

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

$total   = $registrations.Count
$current = 0

foreach ($user in $registrations) {
    $current++
    $progressStatus = "$current of $total - $($user.UserPrincipalName)"
    Write-Progress -Activity 'Processing users' `
                   -Status $progressStatus `
                   -PercentComplete (($current / $total) * 100)

    $hasFido2 = $user.MethodsRegistered -contains 'fido2'
    $hasMfa   = ($user.MethodsRegistered | Where-Object { $_ -notin @('password', 'passwordlessMicrosoftAuthenticator') }).Count -gt 0

    # Determine method category and status
    if ($hasFido2) {
        $authMethod  = 'Passkey (FIDO2)'
        $status      = 'Registered'

        # Fetch the actual FIDO2 method registration date
        try {
            $fido2Methods = Get-MgUserAuthenticationFido2Method `
                -UserId $user.Id `
                -ErrorAction SilentlyContinue

            if ($fido2Methods) {
                $earliest     = ($fido2Methods | Sort-Object CreatedDateTime | Select-Object -First 1).CreatedDateTime
                $registeredOn = ([datetime]$earliest).ToString('dd MMM yyyy')
            } else {
                $registeredOn = 'Unknown'
            }
        } catch {
            $registeredOn = 'Unknown'
        }

    } elseif ($hasMfa) {
        $authMethod   = 'MFA only'
        $status       = 'Not enrolled'
        $registeredOn = 'N/A'
    } else {
        $authMethod   = 'Password only'
        $status       = 'Not enrolled'
        $registeredOn = 'N/A'
    }

    $results.Add([PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName       = $user.DisplayName
        AuthMethod        = $authMethod
        Status            = $status
        RegisteredOn      = $registeredOn
        MethodsRegistered = ($user.MethodsRegistered -join ', ')
    })
}

Write-Progress -Activity 'Processing users' -Completed

#endregion

#region -- Display results ------------------------------------------------------

Write-Host ''
Write-Host ('-' * 95) -ForegroundColor DarkGray
Write-Host ''

# Colour-coded output
$padUpn    = 42
$padMethod = 20
$padStatus = 16
$padDate   = 14

# Header
Write-Host ('UserPrincipalName'.PadRight($padUpn)) -NoNewline -ForegroundColor Green
Write-Host ('AuthMethod'.PadRight($padMethod))      -NoNewline -ForegroundColor Green
Write-Host ('Status'.PadRight($padStatus))           -NoNewline -ForegroundColor Green
Write-Host ('RegisteredOn'.PadRight($padDate))                  -ForegroundColor Green

Write-Host (('-' * ($padUpn - 2)).PadRight($padUpn)) -NoNewline -ForegroundColor DarkGray
Write-Host (('-' * ($padMethod - 2)).PadRight($padMethod)) -NoNewline -ForegroundColor DarkGray
Write-Host (('-' * ($padStatus - 2)).PadRight($padStatus)) -NoNewline -ForegroundColor DarkGray
Write-Host (('-' * ($padDate - 2)).PadRight($padDate))          -ForegroundColor DarkGray

foreach ($r in $results) {
    $upnDisplay = if ($r.UserPrincipalName.Length -gt ($padUpn - 2)) {
        $r.UserPrincipalName.Substring(0, $padUpn - 5) + '...'
    } else { $r.UserPrincipalName }

    $colour = switch ($r.AuthMethod) {
        'Passkey (FIDO2)' { 'Green'  }
        'MFA only'        { 'Yellow' }
        'Password only'   { 'Red'    }
        default           { 'White'  }
    }

    $statusSymbol = if ($r.Status -eq 'Registered') { [char]0x2713 } else { [char]0x2717 }

    Write-Host ($upnDisplay.PadRight($padUpn))                      -NoNewline -ForegroundColor White
    Write-Host ($r.AuthMethod.PadRight($padMethod))                  -NoNewline -ForegroundColor $colour
    Write-Host ("$statusSymbol  $($r.Status)".PadRight($padStatus))  -NoNewline -ForegroundColor $colour
    Write-Host ($r.RegisteredOn.PadRight($padDate))                              -ForegroundColor Cyan
}

Write-Host ''
Write-Host ('-' * 95) -ForegroundColor DarkGray

# Summary
$passkeyCount = ($results | Where-Object { $_.AuthMethod -eq 'Passkey (FIDO2)' }).Count
$mfaOnlyCount = ($results | Where-Object { $_.AuthMethod -eq 'MFA only' }).Count
$pwdOnlyCount = ($results | Where-Object { $_.AuthMethod -eq 'Password only' }).Count
$totalCount   = $results.Count

Write-Host ''
Write-Host ([char]0x2713) -NoNewline -ForegroundColor Green
Write-Host " $passkeyCount of $totalCount users registered a passkey" -NoNewline -ForegroundColor White
Write-Host '   |   ' -NoNewline -ForegroundColor DarkGray
Write-Host "$mfaOnlyCount MFA only" -NoNewline -ForegroundColor Yellow
Write-Host '   |   ' -NoNewline -ForegroundColor DarkGray
Write-Host "$pwdOnlyCount password only" -ForegroundColor Red
Write-Host ''

#endregion

#region -- CSV export -----------------------------------------------------------

if ($ExportCsv) {
    $csvPath = Join-Path $PSScriptRoot "PasskeyStatus_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $results | Select-Object UserPrincipalName, DisplayName, AuthMethod, Status, RegisteredOn |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $csvPath" -ForegroundColor Cyan
}

#endregion

Disconnect-MgGraph | Out-Null
Write-Host 'Disconnected from Microsoft Graph.' -ForegroundColor DarkGray
