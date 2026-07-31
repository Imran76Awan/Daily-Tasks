<#
.SYNOPSIS
    Read-only detection helper for Shadow Credentials abuse of msDS-KeyCredentialLink.

.DESCRIPTION
    Changes nothing and does NOT query Active Directory objects. It looks at the
    two things a defender needs:

      1. Whether the 'Directory Service Changes' audit subcategory is enabled
         (required for Event 5136 to fire) - read via auditpol.
      2. Recent Security Event ID 5136 records where the modified attribute is
         msDS-KeyCredentialLink - i.e. someone added or removed a WHfB key
         credential. For each it reports the actor, the target object and whether
         the value was Added or Deleted.

    Event 5136 is written on domain controllers, so run this on a DC (or point
    -ComputerName at one). On a non-DC it will simply report no 5136 records.

    This is a MONITORING aid, not an attack tool. It reads the event log only.

.PARAMETER ComputerName
    Domain controller to read the Security log from. Defaults to the local machine.

.PARAMETER MaxEvents
    Max number of matching 5136 records to return. Default 50.

.EXAMPLE
    .\Get-ShadowCredentialSignals.ps1

.EXAMPLE
    .\Get-ShadowCredentialSignals.ps1 -ComputerName DC01 -MaxEvents 100

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-shadow-credentials-detection-hardening.html
    Safe   : READ-ONLY. Reads audit policy state and the Security event log only.
    Needs  : Run on / against a DC with 'Audit Directory Service Changes' enabled
             and a SACL auditing writes on the relevant objects.
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [int]$MaxEvents = 50
)

# 1. Is the required audit subcategory enabled locally?
Write-Host ''
Write-Host '  Shadow Credentials - Detection Signals' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
try {
    $ap = auditpol /get /subcategory:"Directory Service Changes" 2>$null
    $line = ($ap | Select-String 'Directory Service Changes')
    if ($line) {
        $enabled = $line -match 'Success'
        $c = if ($enabled) { 'Green' } else { 'Yellow' }
        Write-Host ('  Audit "Directory Service Changes": {0}' -f ($line.ToString().Trim())) -ForegroundColor $c
        if (-not $enabled) {
            Write-Host '  -> Enable Success auditing or Event 5136 will never fire.' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  Could not read the audit subcategory state (run elevated / on a DC).' -ForegroundColor Gray
    }
} catch {
    Write-Host '  auditpol unavailable on this host.' -ForegroundColor Gray
}

# 2. Recent 5136 writes to msDS-KeyCredentialLink
Write-Host ''
Write-Host ('  Event 5136 writes to msDS-KeyCredentialLink (source: {0})' -f $ComputerName) -ForegroundColor Cyan
$results = @()
try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{ LogName = 'Security'; Id = 5136 } -MaxEvents 2000 -ErrorAction Stop
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        if ($data['AttributeLDAPDisplayName'] -eq 'msDS-KeyCredentialLink') {
            $op = switch ($data['OperationType']) {
                '%%14674' { 'Value Added' }
                '%%14675' { 'Value Deleted' }
                default   { $data['OperationType'] }
            }
            $results += [PSCustomObject]@{
                Time      = $e.TimeCreated
                Actor     = $data['SubjectUserName']
                Target    = $data['ObjectDN']
                Operation = $op
            }
        }
    }
} catch {
    Write-Host ('  Could not read Security log from {0}: {1}' -f $ComputerName, $_.Exception.Message) -ForegroundColor Gray
}

$results = $results | Select-Object -First $MaxEvents
if ($results.Count) {
    $results | Format-Table Time, Actor, Operation, Target -AutoSize
    Write-Host '  Review any "Value Added" by an account that is NOT your Entra Connect' -ForegroundColor Yellow
    Write-Host '  sync account or a sanctioned key-management process - especially on' -ForegroundColor Yellow
    Write-Host '  privileged targets.' -ForegroundColor Yellow
} else {
    Write-Host '  No 5136 msDS-KeyCredentialLink records found.' -ForegroundColor Gray
    Write-Host '  (Expected on a non-DC, or if auditing/SACL is not yet configured.)' -ForegroundColor Gray
}
Write-Host ''
