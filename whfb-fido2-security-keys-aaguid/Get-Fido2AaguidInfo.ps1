<#
.SYNOPSIS
    Offline helper to validate a FIDO2 AAGUID and map common ones to a friendly
    vendor/model name, for building Microsoft Entra passkey allow/block lists.

.DESCRIPTION
    Changes nothing and needs no network or tenant connection. Give it an AAGUID
    (128-bit GUID) and it validates the format and looks it up against a small
    built-in map of well-known authenticators. Unknown AAGUIDs are reported as
    such with a pointer to confirm with the vendor or Microsoft's attestation list.

    This is a convenience utility for admins assembling key-restriction lists in
    the Passkey (FIDO2) authentication method policy - it does not query Entra.

.PARAMETER Aaguid
    One or more AAGUIDs to look up. If omitted, prints the built-in known list.

.EXAMPLE
    .\Get-Fido2AaguidInfo.ps1 -Aaguid 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'

.EXAMPLE
    .\Get-Fido2AaguidInfo.ps1        # prints the built-in known-AAGUID reference

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-fido2-security-keys-aaguid.html
    Safe   : READ-ONLY, offline. AAGUID map is a convenience reference, not
             authoritative - always confirm with the vendor / Microsoft MDS.
#>

[CmdletBinding()]
param([string[]]$Aaguid)

# Small, commonly-referenced subset. NOT exhaustive - verify with the vendor.
$known = @{
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' = 'Windows Hello (software)'
    '08987058-cadc-4b81-b6e1-30de50dcbe96' = 'Windows Hello (hardware / VBS)'
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9' = 'Windows Hello (TPM)'
    'ee882879-721c-4913-9775-3dfcce97072a' = 'YubiKey 5 Series'
    'fa2b99dc-9e39-4257-8f92-4a30d23c4118' = 'YubiKey 5 Series (FIPS)'
    '2fc0579f-8113-47ea-b116-bb5a8db9202a' = 'YubiKey 5 Series (newer FW)'
    '90a3ccdf-635c-4729-a248-9b709135078f' = 'Feitian BioPass'
    'de1e552d-db1d-4423-a619-566b625cdc84' = 'Authenticator (device-bound) - example'
}

function Test-Aaguid([string]$g) {
    return ($g -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$')
}

Write-Host ''
Write-Host '  FIDO2 AAGUID Helper' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'

if (-not $Aaguid) {
    Write-Host '  Built-in known AAGUIDs (subset - verify with vendor):'
    $known.GetEnumerator() | Sort-Object Value | ForEach-Object {
        Write-Host ('    {0}  {1}' -f $_.Key, $_.Value)
    }
    Write-Host ''
    Write-Host '  Pass -Aaguid <guid> to validate and identify a specific key.' -ForegroundColor Gray
    Write-Host ''
    return
}

foreach ($g in $Aaguid) {
    $norm = $g.Trim('{','}').ToLower()
    if (-not (Test-Aaguid $g)) {
        Write-Host ('  [INVALID] {0}  - not a well-formed 128-bit GUID' -f $g) -ForegroundColor Red
        continue
    }
    if ($known.ContainsKey($norm)) {
        Write-Host ('  [KNOWN]   {0}  = {1}' -f $norm, $known[$norm]) -ForegroundColor Green
    } else {
        Write-Host ('  [UNKNOWN] {0}  - valid format, not in local map. Confirm with the' -f $norm) -ForegroundColor Yellow
        Write-Host '            vendor or Microsoft attestation list before allow-listing.' -ForegroundColor Yellow
    }
}
Write-Host ''
