<#
.SYNOPSIS
    Read-only audit of the msDS-KeyCredentialLink attribute across Active
    Directory users - how many Windows Hello for Business keys each account
    carries, so you can spot accounts with stale or unexpected keys.

.DESCRIPTION
    Changes nothing. Uses the RSAT ActiveDirectory module to enumerate users
    and report, per account, the number of values in msDS-KeyCredentialLink.
    Accounts with more than -FlagThreshold keys (default 1) are highlighted for
    review, because multiple keys usually mean multiple devices - some of which
    may be retired (orphaned keys) or, rarely, attacker-planted.

    This script reports COUNTS from the native attribute. To decode individual
    key fields (DeviceId, creation time, last-logon), use the community
    DSInternals module as shown in the blog post - decoding the binary blob is
    outside the scope of a dependency-free audit.

.PARAMETER SearchBase
    Optional AD distinguished name to scope the search (e.g. an OU). Defaults to
    the whole domain.

.PARAMETER FlagThreshold
    Flag accounts with more than this many keys. Default 1.

.PARAMETER Csv
    Optional path to export the full result as CSV.

.EXAMPLE
    .\Get-KeyCredentialLinkAudit.ps1

.EXAMPLE
    .\Get-KeyCredentialLinkAudit.ps1 -SearchBase 'OU=Staff,DC=contoso,DC=com' -Csv .\keys.csv

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-msds-keycredentiallink-deep-dive.html
    Safe   : READ-ONLY. Does not add or remove any key credential.
    Needs  : RSAT ActiveDirectory module and rights to read the attribute.
             (Read access to msDS-KeyCredentialLink is broad; write is not.)
#>

[CmdletBinding()]
param(
    [string]$SearchBase,
    [int]$FlagThreshold = 1,
    [string]$Csv
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Warning 'The ActiveDirectory module (RSAT) is not installed on this machine.'
    Write-Warning 'Install RSAT or run this from a domain controller / management server.'
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

$params = @{
    Filter     = '*'
    Properties = 'msDS-KeyCredentialLink'
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

$rows = foreach ($u in (Get-ADUser @params)) {
    $keys = @($u.'msDS-KeyCredentialLink')
    [PSCustomObject]@{
        SamAccountName = $u.SamAccountName
        Name           = $u.Name
        KeyCount       = $keys.Count
        Flagged        = ($keys.Count -gt $FlagThreshold)
    }
}

$withKeys = @($rows | Where-Object KeyCount -gt 0)
$flagged  = @($rows | Where-Object Flagged)

Write-Host ''
Write-Host '  msDS-KeyCredentialLink Audit' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  Users scanned            : {0}' -f $rows.Count)
Write-Host ('  Users with >=1 WHfB key  : {0}' -f $withKeys.Count)
Write-Host ('  Users over threshold({0}) : {1}' -f $FlagThreshold, $flagged.Count) -ForegroundColor Yellow
Write-Host '  ------------------------------------------------------------'
if ($flagged.Count) {
    $flagged | Sort-Object KeyCount -Descending |
        Select-Object SamAccountName, Name, KeyCount |
        Format-Table -AutoSize
    Write-Host '  Review flagged accounts with DSInternals to decode each key''s DeviceId.' -ForegroundColor Gray
} else {
    Write-Host '  No accounts over the key threshold.' -ForegroundColor Green
}

if ($Csv) {
    $rows | Sort-Object KeyCount -Descending | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
    Write-Host ('  Full results exported to {0}' -f $Csv)
}
