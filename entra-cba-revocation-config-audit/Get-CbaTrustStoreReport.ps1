#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Read-only audit of the Microsoft Entra certificate-based authentication (CBA)
    trust store. Lists every trusted certificate authority (CA) with its
    certificate revocation list (CRL) distribution point, flags any CA that has no
    CRL URL configured, and reports the CBA authentication method policy (default
    single-factor vs multi-factor binding and whether "Require CRL validation" is
    enforced).

.DESCRIPTION
    When an organisation revokes a certificate (for example when someone leaves),
    Microsoft Entra ID can only see that revocation if it can download the issuing
    CA's CRL. Per Microsoft documentation, if a trusted CA has NO CRL distribution
    point configured in the Entra CBA trust store, Entra ID performs NO revocation
    checking for certificates issued by that CA - a revoked certificate keeps
    authenticating until it expires. This is silent: the portal shows CBA as
    enabled and healthy.

    This script reads three surfaces and reports on them. It NEVER writes, creates,
    modifies, deletes, enables, disables, resets, or remediates anything. It is a
    pure read/audit tool.

        1. Legacy trust store
           GET /v1.0/organization/{id}/certificateBasedAuthConfiguration
           (equivalent cmdlet: Get-MgOrganizationCertificateBasedAuthConfiguration)
           Scope: Organization.Read.All

        2. New PKI-based trust store (recommended by Microsoft)
           GET /v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations
           and .../{id}/certificateAuthorities
           (equivalent cmdlet: Get-MgDirectoryPublicKeyInfrastructureCertificateBasedAuthConfigurationCertificateAuthority)
           Scope: PublicKeyInfrastructure.Read.All

        3. CBA authentication method policy (X509Certificate)
           GET /v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/X509Certificate
           (equivalent cmdlet: Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration)
           Scope: Policy.Read.AuthenticationMethod

    A CA is flagged as a finding when it has no certificateRevocationListUrl AND
    the policy's "Require CRL validation" (crlValidationConfiguration.state) is not
    enabled, or the CA is not exempted from CRL validation. The default
    authentication mode (x509CertificateSingleFactor / x509CertificateMultiFactor)
    is reported so an over-permissive binding can be reviewed.

.PARAMETER TenantId
    Entra tenant ID (GUID) for app-only certificate authentication.

.PARAMETER ClientId
    App registration (client) ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Thumbprint of the client certificate in the local certificate store, used for
    app-only authentication.

.PARAMETER UseDeviceCode
    Interactive device-code sign-in fallback instead of app-only certificate auth.
    Useful for an admin running the audit ad hoc.

.PARAMETER TestCrlReachability
    Optional. For each CA that has a CRL URL, performs a read-only HTTP GET to check
    the distribution point responds. This only reads the CRL; it changes nothing.

.PARAMETER ExportCsv
    Optional. Write the per-CA results to a CSV file.

.PARAMETER CsvPath
    Optional. Destination path for the CSV. Defaults to a timestamped file in the
    current directory when -ExportCsv is used.

.EXAMPLE
    .\Get-CbaTrustStoreReport.ps1 -TenantId $tid -ClientId $cid -CertificateThumbprint $thumb

    Runs the audit using app-only certificate authentication.

.EXAMPLE
    .\Get-CbaTrustStoreReport.ps1 -UseDeviceCode -TestCrlReachability

    Runs the audit interactively and also tests that each configured CRL URL is
    reachable (read-only).

.EXAMPLE
    .\Get-CbaTrustStoreReport.ps1 -UseDeviceCode -ExportCsv -CsvPath C:\Temp\cba-audit.csv

    Runs the audit interactively and exports the per-CA table to CSV.

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Report-only. Least-privilege READ scopes only:
        Organization.Read.All, PublicKeyInfrastructure.Read.All, Policy.Read.AuthenticationMethod
    Exit codes: 0 = clean (no findings), 1 = script/query error, 2 = findings detected.
    ASCII-only source. Tested with PowerShell 7 and the Microsoft.Graph.Authentication module.
#>

[CmdletBinding(DefaultParameterSetName = 'AppOnly')]
param(
    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $TenantId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $ClientId,

    [Parameter(ParameterSetName = 'AppOnly', Mandatory = $true)]
    [string] $CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
    [switch] $UseDeviceCode,

    [Parameter()]
    [switch] $TestCrlReachability,

    [Parameter()]
    [switch] $ExportCsv,

    [Parameter()]
    [string] $CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fail-loud state. Any query/connection failure sets this; the script then exits 1
# rather than printing a misleading "all clean" summary.
$script:hadError = $false
$script:findings = 0

$RequiredScopes = @(
    'Organization.Read.All',
    'PublicKeyInfrastructure.Read.All',
    'Policy.Read.AuthenticationMethod'
)

function Write-Section {
    param([string] $Text)
    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host "  $Text"
    Write-Host ('=' * 70)
}

function Invoke-GraphGet {
    # Thin wrapper around Invoke-MgGraphRequest that returns $null for a genuine
    # "resource not configured" (404) response, and rethrows everything else so a
    # permission or throttling error is never silently swallowed.
    param([string] $Uri)
    try {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '\b404\b' -or $msg -match 'NotFound' -or $msg -match 'does not exist' -or $msg -match 'Resource .* not found') {
            return $null
        }
        throw
    }
}

# ---------------------------------------------------------------------------
# 1. Connect (read-only scopes)
# ---------------------------------------------------------------------------
try {
    Write-Host 'Connecting to Microsoft Graph (read-only scopes)...'
    if ($UseDeviceCode) {
        Connect-MgGraph -Scopes $RequiredScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
    }
    else {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    $ctx = Get-MgContext -ErrorAction Stop
    if (-not $ctx) { throw 'No Graph context after connect.' }
    Write-Host ("Connected. Tenant: {0}" -f $ctx.TenantId)
}
catch {
    Write-Error ("Failed to connect to Microsoft Graph: {0}" -f $_.Exception.Message)
    exit 1
}

# Collector for all CA rows across both trust-store surfaces.
$caRows = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# 2. Legacy trust store: /organization/{id}/certificateBasedAuthConfiguration
# ---------------------------------------------------------------------------
try {
    $org = Invoke-GraphGet -Uri '/v1.0/organization?$select=id,displayName'
    if (-not $org -or -not $org.value) { throw 'Could not read organization object.' }
    $orgId = $org.value[0].id

    $legacy = Invoke-GraphGet -Uri ("/v1.0/organization/{0}/certificateBasedAuthConfiguration" -f $orgId)
    $legacyCas = @()
    if ($legacy -and $legacy.value) {
        foreach ($cfg in $legacy.value) {
            if ($cfg.PSObject.Properties.Name -contains 'certificateAuthorities' -and $cfg.certificateAuthorities) {
                $legacyCas += $cfg.certificateAuthorities
            }
        }
    }

    foreach ($ca in $legacyCas) {
        $crl = if ($ca.PSObject.Properties.Name -contains 'certificateRevocationListUrl') { $ca.certificateRevocationListUrl } else { $null }
        $delta = if ($ca.PSObject.Properties.Name -contains 'deltaCertificateRevocationListUrl') { $ca.deltaCertificateRevocationListUrl } else { $null }
        $caRows.Add([pscustomobject]@{
            Surface       = 'Legacy'
            IsRoot        = [bool] $ca.isRootAuthority
            Issuer        = [string] $ca.issuer
            Ski           = [string] $ca.issuerSki
            CrlUrl        = [string] $crl
            DeltaCrlUrl   = [string] $delta
            CrlReachable  = 'not-tested'
        })
    }
    Write-Host ("Legacy trust store CAs found : {0}" -f $legacyCas.Count)
}
catch {
    Write-Error ("Failed reading legacy CBA trust store: {0}" -f $_.Exception.Message)
    $script:hadError = $true
}

# ---------------------------------------------------------------------------
# 3. New PKI-based trust store: /directory/publicKeyInfrastructure/...
# ---------------------------------------------------------------------------
try {
    $pkis = Invoke-GraphGet -Uri '/v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations'
    $pkiCaCount = 0
    if ($pkis -and $pkis.value) {
        foreach ($pki in $pkis.value) {
            $cas = Invoke-GraphGet -Uri ("/v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations/{0}/certificateAuthorities" -f $pki.id)
            if ($cas -and $cas.value) {
                foreach ($ca in $cas.value) {
                    $type = if ($ca.PSObject.Properties.Name -contains 'certificateAuthorityType') { $ca.certificateAuthorityType } else { '' }
                    $crl = if ($ca.PSObject.Properties.Name -contains 'certificateRevocationListUrl') { $ca.certificateRevocationListUrl } else { $null }
                    # Note: the PKI resource spells the delta property with a lower-case 'c'.
                    $delta = if ($ca.PSObject.Properties.Name -contains 'deltacertificateRevocationListUrl') { $ca.deltacertificateRevocationListUrl } else { $null }
                    $caRows.Add([pscustomobject]@{
                        Surface       = 'PKI'
                        IsRoot        = ($type -eq 'root')
                        Issuer        = [string] $ca.issuer
                        Ski           = [string] $ca.issuerSubjectKeyIdentifier
                        CrlUrl        = [string] $crl
                        DeltaCrlUrl   = [string] $delta
                        CrlReachable  = 'not-tested'
                    })
                    $pkiCaCount++
                }
            }
        }
    }
    Write-Host ("PKI trust store CAs found    : {0}" -f $pkiCaCount)
}
catch {
    Write-Error ("Failed reading PKI-based CBA trust store: {0}" -f $_.Exception.Message)
    $script:hadError = $true
}

# ---------------------------------------------------------------------------
# 4. CBA authentication method policy (X509Certificate)
# ---------------------------------------------------------------------------
$defaultMode   = 'unknown'
$policyState   = 'unknown'
$ruleCount     = 0
$crlValidation = 'unknown'
$exemptedSkis  = @()
try {
    $x509 = Invoke-GraphGet -Uri '/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/X509Certificate'
    if ($x509) {
        if ($x509.PSObject.Properties.Name -contains 'state') { $policyState = [string] $x509.state }

        if ($x509.PSObject.Properties.Name -contains 'authenticationModeConfiguration' -and $x509.authenticationModeConfiguration) {
            $amc = $x509.authenticationModeConfiguration
            if ($amc.PSObject.Properties.Name -contains 'x509CertificateAuthenticationDefaultMode') {
                $defaultMode = [string] $amc.x509CertificateAuthenticationDefaultMode
            }
            if ($amc.PSObject.Properties.Name -contains 'rules' -and $amc.rules) {
                $ruleCount = @($amc.rules).Count
            }
        }

        if ($x509.PSObject.Properties.Name -contains 'crlValidationConfiguration' -and $x509.crlValidationConfiguration) {
            $cvc = $x509.crlValidationConfiguration
            if ($cvc.PSObject.Properties.Name -contains 'state') { $crlValidation = [string] $cvc.state }
            if ($cvc.PSObject.Properties.Name -contains 'exemptedCertificateAuthoritiesSubjectKeyIdentifiers' -and $cvc.exemptedCertificateAuthoritiesSubjectKeyIdentifiers) {
                $exemptedSkis = @($cvc.exemptedCertificateAuthoritiesSubjectKeyIdentifiers)
            }
        }
    }
    else {
        Write-Warning 'X509Certificate authentication method configuration not returned (CBA may not be configured).'
    }
}
catch {
    Write-Error ("Failed reading CBA authentication method policy: {0}" -f $_.Exception.Message)
    $script:hadError = $true
}

# ---------------------------------------------------------------------------
# 5. Optional read-only CRL reachability test
# ---------------------------------------------------------------------------
if ($TestCrlReachability) {
    foreach ($row in $caRows) {
        if ([string]::IsNullOrWhiteSpace($row.CrlUrl)) {
            $row.CrlReachable = 'no-url'
            continue
        }
        try {
            $resp = Invoke-WebRequest -Uri $row.CrlUrl -Method Get -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            $row.CrlReachable = ("HTTP {0}" -f [int] $resp.StatusCode)
        }
        catch {
            # A CRL endpoint that does not respond is a finding, not a script error.
            $row.CrlReachable = ("UNREACHABLE: {0}" -f $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------------------
# 6. If any required query failed, stop now. Never report "clean" on bad data.
# ---------------------------------------------------------------------------
if ($script:hadError) {
    Write-Error 'One or more Graph queries failed. Results are incomplete; not reporting a status. Exiting 1.'
    exit 1
}

# ---------------------------------------------------------------------------
# 7. Report
# ---------------------------------------------------------------------------
$crlValidationEnabled = ($crlValidation -eq 'enabled')

Write-Section ("ENTRA CBA TRUST STORE REPORT - {0}" -f (Get-Date -Format 'dd MMM yyyy HH:mm'))
Write-Host ("  Total trusted CAs         : {0}" -f $caRows.Count)
Write-Host ("  CBA policy state          : {0}" -f $policyState)
Write-Host ("  Default auth mode          : {0}" -f $defaultMode)
Write-Host ("  Strong-auth rules defined  : {0}" -f $ruleCount)
Write-Host ("  Require CRL validation     : {0}" -f $crlValidation)
Write-Host ("  CAs exempted from CRL check: {0}" -f $exemptedSkis.Count)

Write-Section 'CERTIFICATE AUTHORITIES'
if ($caRows.Count -eq 0) {
    Write-Host '  No trusted CAs found in either trust store.'
}
foreach ($row in $caRows) {
    $missingCrl = [string]::IsNullOrWhiteSpace($row.CrlUrl)
    $isExempt   = $exemptedSkis -contains $row.Ski
    $isFinding  = $missingCrl -and -not $crlValidationEnabled -and -not $isExempt

    if ($isFinding) { $script:findings++ }

    $status =
        if ($missingCrl -and $isExempt)               { 'NO CRL (exempted)' }
        elseif ($missingCrl -and $crlValidationEnabled) { 'NO CRL (blocked by Require-CRL)' }
        elseif ($missingCrl)                          { 'FINDING: NO CRL - revocation NOT checked' }
        elseif ($row.CrlReachable -like 'UNREACHABLE*') { 'FINDING: CRL unreachable' }
        else                                          { 'OK' }

    Write-Host ''
    Write-Host ("  Surface        : {0}" -f $row.Surface)
    Write-Host ("  Root authority : {0}" -f $row.IsRoot)
    Write-Host ("  Issuer         : {0}" -f $row.Issuer)
    Write-Host ("  Issuer SKI     : {0}" -f $row.Ski)
    Write-Host ("  CRL URL        : {0}" -f $(if ($missingCrl) { '<none>' } else { $row.CrlUrl }))
    Write-Host ("  Delta CRL URL  : {0}" -f $(if ([string]::IsNullOrWhiteSpace($row.DeltaCrlUrl)) { '<none>' } else { $row.DeltaCrlUrl }))
    if ($TestCrlReachability) { Write-Host ("  CRL reachable  : {0}" -f $row.CrlReachable) }
    Write-Host ("  STATUS         : {0}" -f $status)
}

# Advisory: over-permissive binding (informational, does not change exit code by itself).
$bindingAdvisory = $false
if ($defaultMode -eq 'x509CertificateMultiFactor' -and $ruleCount -eq 0) {
    $bindingAdvisory = $true
}

Write-Section 'SUMMARY'
Write-Host ("  CAs with no revocation checking (findings): {0}" -f $script:findings)
if ($TestCrlReachability) {
    $unreachable = @($caRows | Where-Object { $_.CrlReachable -like 'UNREACHABLE*' }).Count
    Write-Host ("  CAs with an unreachable CRL URL           : {0}" -f $unreachable)
}
if (-not $crlValidationEnabled) {
    Write-Host '  ADVISORY: "Require CRL validation" is NOT enabled - a CA with no CRL will silently skip revocation.'
}
if ($bindingAdvisory) {
    Write-Host '  ADVISORY: default mode is multi-factor with no granular rules - every trusted certificate satisfies MFA. Confirm this is intended.'
}

# ---------------------------------------------------------------------------
# 8. Optional CSV export
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $CsvPath = Join-Path -Path (Get-Location) -ChildPath ("CbaTrustStoreReport-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    try {
        $caRows | Select-Object Surface, IsRoot, Issuer, Ski, CrlUrl, DeltaCrlUrl, CrlReachable |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host ("CSV written to: {0}" -f $CsvPath)
    }
    catch {
        Write-Error ("Failed to write CSV: {0}" -f $_.Exception.Message)
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 9. Exit code
# ---------------------------------------------------------------------------
Write-Host ''
if ($script:findings -gt 0) {
    Write-Host ("RESULT: {0} finding(s) detected." -f $script:findings)
    exit 2
}
else {
    Write-Host 'RESULT: No revocation-config findings detected.'
    exit 0
}
