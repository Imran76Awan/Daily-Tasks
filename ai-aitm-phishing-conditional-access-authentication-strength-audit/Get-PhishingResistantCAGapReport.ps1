<#
.SYNOPSIS
    Reports which Conditional Access policies in a Microsoft Entra ID tenant enforce a
    phishing-resistant authentication strength versus policies that only require generic
    "MFA" (any method) or a non-phishing-resistant authentication strength.

.DESCRIPTION
    AiTM (adversary-in-the-middle) reverse-proxy phishing kits relay a real session in real
    time, so any authentication method that can be entered into a phishing page - a password,
    an SMS code, a TOTP code, or an "Approve" push - can be relayed straight through and the
    resulting session token stolen. Windows Hello for Business, FIDO2 security keys, and
    Entra certificate-based authentication (multifactor) cannot be relayed this way because
    the cryptographic exchange is bound to the real origin.

    Entra ID Conditional Access lets an administrator require the built-in "Phishing-resistant
    MFA strength" authentication strength policy, or a custom authentication strength whose
    allowed combinations only include phishing-resistant methods. Many tenants instead use the
    older "Require multifactor authentication" grant control (builtInControls = mfa), which
    accepts ANY registered MFA method, including the ones AiTM kits defeat every day.

    This script is READ-ONLY. It calls:
      GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies

    For every policy that is enabled or in report-only mode and that actually grants access
    (not a pure "block" policy), it classifies the grant control as one of:
      PhishingResistant   - authenticationStrength is set and every allowed combination in it
                             is one of: windowsHelloForBusiness, fido2, x509CertificateMultiFactor
      MixedStrength        - authenticationStrength is set but ALSO allows at least one
                             non-phishing-resistant combination (for example password+sms)
      GenericMfaOnly        - builtInControls contains "mfa" and no authenticationStrength is set
      NoMfaOrStrength      - the policy grants access without requiring MFA or an authentication
                             strength at all (compliant device only, and so on)

    It makes no changes. It performs GET calls only.

.NOTES
    Author:   EndpointWeekly
    Blog URL: https://endpointweekly.com/blog/ai-aitm-phishing-conditional-access-authentication-strength-audit.html
    Requires: Microsoft.Graph.Authentication module (Connect-MgGraph, Invoke-MgGraphRequest)
    Graph permission (least privilege): Policy.Read.All (delegated or application)
    Exit codes:
      0 = clean, no gaps found (every grant-enabled policy enforces phishing-resistant strength)
      1 = findings, at least one policy relies on generic MFA or a mixed strength
      2 = error (could not authenticate or could not read policies)

.EXAMPLE
    .\Get-PhishingResistantCAGapReport.ps1 -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "11111111-1111-1111-1111-111111111111" `
        -CertificateThumbprint "AAAABBBBCCCCDDDDEEEEFFFF00001111AAAABBBB"

.EXAMPLE
    .\Get-PhishingResistantCAGapReport.ps1 -UseDeviceCode -ExportCsv -CsvPath "C:\Reports\ca-authstrength-gap.csv"
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
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = ".\ca-authstrength-gap-report.csv",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeReportOnly
)

$script:hadError = $false

# The three method modes that Entra ID documents as satisfying the built-in
# "Phishing-resistant MFA strength" authentication strength. Source:
# https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths
$script:PhishingResistantMethods = @(
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor"
)

function Connect-ToGraph {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceCode
    )

    try {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            Write-Error "The Microsoft.Graph.Authentication module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
            $script:hadError = $true
            return $false
        }

        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

        if ($UseDeviceCode) {
            Write-Host "Connecting with delegated device code sign-in. Scope requested: Policy.Read.All" -ForegroundColor Cyan
            Connect-MgGraph -Scopes "Policy.Read.All" -UseDeviceCode -NoWelcome -ErrorAction Stop
            return $true
        }

        if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            Write-Error "App-only auth requires -TenantId, -ClientId, and -CertificateThumbprint. Or pass -UseDeviceCode for interactive sign-in."
            $script:hadError = $true
            return $false
        }

        Write-Host "Connecting with app-only certificate auth (TenantId: $TenantId)" -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        $script:hadError = $true
        return $false
    }
}

function Get-AllConditionalAccessPolicies {
    $allPolicies = New-Object System.Collections.Generic.List[object]
    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($response.value) {
                foreach ($item in $response.value) { $allPolicies.Add($item) }
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)

        return $allPolicies
    }
    catch {
        Write-Error "Failed to read Conditional Access policies: $($_.Exception.Message)"
        $script:hadError = $true
        return @()
    }
}

function Test-IsPhishingResistantCombination {
    param([string]$Combination)

    # A combination string can itself contain a comma-joined set, e.g. "password,sms".
    # A combination only counts as phishing-resistant if it is EXACTLY one of the three
    # single-factor phishing-resistant modes - never a comma-joined fallback pairing.
    return ($script:PhishingResistantMethods -contains $Combination)
}

function Get-GrantControlVerdict {
    param($Policy)

    $grant = $Policy.grantControls

    if ($null -eq $grant) {
        return [pscustomobject]@{
            Verdict = "NoGrantControl"
            Detail  = "No grant control configured (session-only or misconfigured policy)."
        }
    }

    $builtIn = @()
    if ($grant.builtInControls) { $builtIn = @($grant.builtInControls) }

    if ($builtIn -contains "block") {
        return [pscustomobject]@{
            Verdict = "Block"
            Detail  = "Policy blocks access. Not an authentication-strength gap."
        }
    }

    $strength = $grant.authenticationStrength

    if ($null -ne $strength -and $strength.allowedCombinations) {
        $combos = @($strength.allowedCombinations)
        $nonResistant = @($combos | Where-Object { -not (Test-IsPhishingResistantCombination $_) })

        if ($nonResistant.Count -eq 0) {
            return [pscustomobject]@{
                Verdict = "PhishingResistant"
                Detail  = "Authentication strength '$($strength.displayName)' allows only: $($combos -join ', ')"
            }
        }
        else {
            return [pscustomobject]@{
                Verdict = "MixedStrength"
                Detail  = "Authentication strength '$($strength.displayName)' also allows non-phishing-resistant combos: $($nonResistant -join ', ')"
            }
        }
    }

    if ($builtIn -contains "mfa") {
        return [pscustomobject]@{
            Verdict = "GenericMfaOnly"
            Detail  = "builtInControls = mfa, no authenticationStrength set. Any registered MFA method satisfies this, including SMS, voice, and push - all relayable by an AiTM phishing proxy."
        }
    }

    if ($builtIn.Count -gt 0) {
        return [pscustomobject]@{
            Verdict = "NoMfaOrStrength"
            Detail  = "Grant control(s) present ($($builtIn -join ', ')) but none require MFA or an authentication strength."
        }
    }

    return [pscustomobject]@{
        Verdict = "NoMfaOrStrength"
        Detail  = "Grant control object present but empty of usable controls."
    }
}

function Get-TargetSummary {
    param($Policy)

    $users = $Policy.conditions.users
    if ($null -eq $users) { return "Unknown" }

    $includeAll = $users.includeUsers -contains "All"
    $includeCount = 0
    if ($users.includeUsers) { $includeCount += @($users.includeUsers | Where-Object { $_ -ne "All" }).Count }
    if ($users.includeGroups) { $includeCount += @($users.includeGroups).Count }
    if ($users.includeRoles) { $includeCount += @($users.includeRoles).Count }

    if ($includeAll) { return "All users" }
    if ($includeCount -gt 0) { return "$includeCount targeted user/group/role entr$(if($includeCount -eq 1){'y'}else{'ies'})" }
    return "No users included"
}

function Invoke-PhishingResistantAudit {
    param(
        [System.Collections.Generic.List[object]]$Policies,
        [switch]$IncludeReportOnly
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($policy in $Policies) {
        $state = $policy.state

        if ($state -eq "disabled") { continue }
        if ($state -eq "enabledForReportingButNotEnforced" -and -not $IncludeReportOnly) { continue }

        $verdict = Get-GrantControlVerdict -Policy $policy
        if ($verdict.Verdict -eq "Block") { continue }

        $flagged = $verdict.Verdict -in @("GenericMfaOnly", "MixedStrength", "NoMfaOrStrength")

        $results.Add([pscustomobject]@{
            PolicyId       = $policy.id
            DisplayName    = $policy.displayName
            State          = $state
            Target         = Get-TargetSummary -Policy $policy
            Verdict        = $verdict.Verdict
            Flagged        = $flagged
            Detail         = $verdict.Detail
        })
    }

    return $results
}

# ---- Main ----

$connected = Connect-ToGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -UseDeviceCode:$UseDeviceCode
if (-not $connected) {
    exit 2
}

$policies = Get-AllConditionalAccessPolicies
if ($script:hadError) {
    exit 2
}

if ($policies.Count -eq 0) {
    Write-Host "No Conditional Access policies were returned. Nothing to audit." -ForegroundColor Yellow
    exit 0
}

$results = Invoke-PhishingResistantAudit -Policies $policies -IncludeReportOnly:$IncludeReportOnly

$flaggedResults = @($results | Where-Object { $_.Flagged })
$cleanResults = @($results | Where-Object { -not $_.Flagged })

Write-Host ""
Write-Host "=== Phishing-Resistant Authentication Strength Audit ===" -ForegroundColor Cyan
Write-Host "Policies evaluated (enabled$(if($IncludeReportOnly){' + report-only'})): $($results.Count)" -ForegroundColor Cyan
Write-Host ""

if ($cleanResults.Count -gt 0) {
    Write-Host "-- Enforcing phishing-resistant authentication strength --" -ForegroundColor Green
    $cleanResults | Where-Object { $_.Verdict -eq "PhishingResistant" } | ForEach-Object {
        Write-Host ("  [OK] {0}  ({1})  Target: {2}" -f $_.DisplayName, $_.PolicyId, $_.Target) -ForegroundColor Green
    }
    Write-Host ""
}

if ($flaggedResults.Count -gt 0) {
    Write-Host "-- Gaps: relying on generic MFA or a non-phishing-resistant strength --" -ForegroundColor Red
    foreach ($item in $flaggedResults) {
        Write-Host ("  [{0}] {1}  ({2})  Target: {3}" -f $item.Verdict, $item.DisplayName, $item.PolicyId, $item.Target) -ForegroundColor Yellow
        Write-Host ("        {0}" -f $item.Detail) -ForegroundColor DarkYellow
    }
    Write-Host ""
}

Write-Host ("Summary: {0} phishing-resistant, {1} flagged out of {2} grant-enabled policies." -f `
    (@($results | Where-Object { $_.Verdict -eq 'PhishingResistant' }).Count), $flaggedResults.Count, $results.Count) -ForegroundColor Cyan

if ($ExportCsv) {
    try {
        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "CSV report written to: $CsvPath" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Failed to write CSV: $($_.Exception.Message)"
        exit 2
    }
}

if ($flaggedResults.Count -gt 0) {
    exit 1
}
else {
    exit 0
}
