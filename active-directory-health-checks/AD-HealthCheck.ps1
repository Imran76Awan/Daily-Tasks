<#
.SYNOPSIS
    10 Essential PowerShell Commands for Active Directory Administrators

.DESCRIPTION
    A reference script covering the 10 most important Active Directory health-check
    and administration commands. Includes DC enumeration, replication status, FSMO
    roles, stale account cleanup, locked account detection, password policy review,
    group membership audit, and connectivity testing.

    All commands require the Active Directory PowerShell module (RSAT: AD DS Tools).
    Run on a domain-joined machine with appropriate permissions.

.AUTHOR
    Imran Awan — EndpointWeekly (https://endpointweekly.com)

.NOTES
    Module    : ActiveDirectory
    Requires  : RSAT: Active Directory Domain Services and Lightweight Directory Tools
    Install   : Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Min OS    : Windows 10 / Windows Server 2016
    Tested on : Windows Server 2022, Windows 11
#>

#Requires -Modules ActiveDirectory

# ── 0. Prerequisites ─────────────────────────────────────────────────────────
# Verify the AD module is available before running anything else
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Warning "ActiveDirectory module not found. Install RSAT:"
    Write-Warning "Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
    return
}
Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "ActiveDirectory module loaded." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 1 — List all Domain Controllers
# Returns DC name, site, OS, and IP for every DC in the domain.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 1. Domain Controllers ===" -ForegroundColor Cyan
Get-ADDomainController -Filter * |
    Select-Object Name, Site, OperatingSystem, IPv4Address, IsGlobalCatalog |
    Format-Table -AutoSize


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 2 — Check AD Replication Status
# Identifies any replication failures between DCs.
# A healthy environment shows 0 failures and recent LastReplicationSuccess.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 2. Replication Status ===" -ForegroundColor Cyan
Get-ADReplicationPartnerMetadata -Target * -Scope Domain |
    Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult,
                  ConsecutiveReplicationFailures |
    Format-Table -AutoSize


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 3 — FSMO Role Holders
# Identifies which DCs hold each of the 5 operations master roles.
# Domain-level roles: PDC Emulator, RID Master, Infrastructure Master
# Forest-level roles: Schema Master, Domain Naming Master
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 3. FSMO Role Holders ===" -ForegroundColor Cyan
$domain = Get-ADDomain
$forest = Get-ADForest
[PSCustomObject]@{
    'PDC Emulator'           = $domain.PDCEmulator
    'RID Master'             = $domain.RIDMaster
    'Infrastructure Master'  = $domain.InfrastructureMaster
    'Schema Master'          = $forest.SchemaMaster
    'Domain Naming Master'   = $forest.DomainNamingMaster
}


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 4 — Domain and Forest Functional Levels
# Lower functional levels restrict which features are available.
# Windows Server 2016 level is the minimum recommended for modern deployments.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 4. Functional Levels ===" -ForegroundColor Cyan
[PSCustomObject]@{
    'Domain Name'             = $domain.DNSRoot
    'Domain Functional Level' = $domain.DomainMode
    'Forest Functional Level' = $forest.ForestMode
    'Forest Root Domain'      = $forest.RootDomain
}


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 5 — Domain Admins Group Members
# Any account in Domain Admins has unrestricted domain access.
# Audit this list regularly — it should be small and reviewed.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 5. Domain Admins Membership ===" -ForegroundColor Cyan
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass |
    Sort-Object ObjectClass, Name |
    Format-Table -AutoSize


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 6 — Locked-Out User Accounts
# Returns all currently locked accounts across the domain.
# Frequent lockouts for a single account indicate credential spraying or a
# misconfigured service account.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 6. Locked-Out Accounts ===" -ForegroundColor Cyan
Search-ADAccount -LockedOut |
    Select-Object Name, SamAccountName, LockedOut, BadLogonCount, PasswordLastSet |
    Sort-Object BadLogonCount -Descending |
    Format-Table -AutoSize


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 7 — Stale User Accounts (90+ days inactive)
# Accounts that have not logged in for 90 days should be reviewed and disabled.
# Stale accounts are a prime target for credential-based attacks.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 7. Stale Users (90+ days) ===" -ForegroundColor Cyan
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
           -Properties LastLogonDate, PasswordLastSet, EmailAddress |
    Where-Object { $null -ne $_.LastLogonDate } |
    Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet |
    Sort-Object LastLogonDate |
    Export-Csv "$env:TEMP\StaleUsers.csv" -NoTypeInformation
Write-Host "Stale users exported to $env:TEMP\StaleUsers.csv" -ForegroundColor Yellow


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 8 — Password Policy (Default Domain Policy)
# Reviews minimum password age, complexity, length, and lockout thresholds.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 8. Default Domain Password Policy ===" -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy |
    Select-Object MinPasswordLength, PasswordHistoryCount, MaxPasswordAge,
                  MinPasswordAge, LockoutThreshold, LockoutDuration,
                  LockoutObservationWindow, ComplexityEnabled |
    Format-List


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 9 — DC Connectivity Test
# Verifies that all DCs are reachable on the essential AD ports:
# 389 (LDAP), 636 (LDAPS), 88 (Kerberos), 445 (SMB/Netlogon), 3268 (GC)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 9. DC Port Connectivity ===" -ForegroundColor Cyan
$adPorts  = @(88, 389, 445, 636, 3268)
$dcNames  = (Get-ADDomainController -Filter *).Name
$results  = foreach ($dc in $dcNames) {
    foreach ($port in $adPorts) {
        $test = Test-NetConnection -ComputerName $dc -Port $port -WarningAction SilentlyContinue
        [PSCustomObject]@{
            DC      = $dc
            Port    = $port
            Service = switch ($port) {
                88   { 'Kerberos' }
                389  { 'LDAP'     }
                445  { 'SMB'      }
                636  { 'LDAPS'    }
                3268 { 'GC LDAP'  }
            }
            Reachable = $test.TcpTestSucceeded
        }
    }
}
$results | Sort-Object DC, Port | Format-Table -AutoSize


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND 10 — Disabled Computer Accounts Still in Production OUs
# Disabled computers left in production OUs create noise in reports and
# can cause Group Policy processing issues for users if they share the same OU.
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== 10. Disabled Computer Accounts ===" -ForegroundColor Cyan
Get-ADComputer -Filter { Enabled -eq $false } -Properties LastLogonDate, OperatingSystem |
    Select-Object Name, LastLogonDate, OperatingSystem, DistinguishedName |
    Sort-Object LastLogonDate |
    Export-Csv "$env:TEMP\DisabledComputers.csv" -NoTypeInformation
Write-Host "Disabled computers exported to $env:TEMP\DisabledComputers.csv" -ForegroundColor Yellow

Write-Host "`nHealth check complete." -ForegroundColor Green
