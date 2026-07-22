<#
.SYNOPSIS
    Audits whether BitLocker-encrypted Windows devices ACTUALLY have a recovery key escrowed to
    Microsoft Entra ID — not just whether the device reports itself as encrypted.

.DESCRIPTION
    "Encrypted" and "recoverable" are two different claims about a BitLocker volume. A device can
    be genuinely, fully encrypted and still have no retrievable recovery key anywhere your
    organisation controls — if that happens, a routine firmware update, TPM clear, motherboard
    swap, or Secure Boot certificate change that triggers a recovery prompt results in PERMANENT
    DATA LOSS, because there is no way to unlock the volume without the recovery key or the
    original platform state.

    IMPORTANT — this script covers ONE of the two BitLocker recovery key escrow destinations:

      * Entra-joined / Intune-managed devices escrow their recovery key to Microsoft Entra ID.
        This script queries that path via Microsoft Graph.

      * Hybrid-joined / GPO-managed devices escrow their recovery key to ON-PREM ACTIVE DIRECTORY,
        stored as an msFVE-RecoveryInformation object under the computer object. This is NOT
        visible to Microsoft Graph and is NOT covered by this script. Auditing that path requires
        a separate on-prem query against Active Directory, e.g.:

            $computer = Get-ADComputer -Identity "<hostname>"
            Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' `
                -SearchBase $computer.DistinguishedName `
                -Properties msFVE-RecoveryPassword, msFVE-RecoveryGuid, whenCreated

        That query requires the ActiveDirectory PowerShell module and connectivity to a domain
        controller, and is a genuinely different script pattern (Windows-integrated auth against
        AD, not an app registration / OAuth token against Graph). It is deliberately NOT bundled
        into this script as a guessed/unverified implementation — if your fleet includes hybrid-
        joined devices, run that query separately and combine the results with this report before
        drawing any conclusion about total fleet-wide escrow coverage.

    What this script does:

      1. Connects to Microsoft Graph using either app-only certificate authentication or
         interactive device-code sign-in.
      2. Enumerates managed Windows devices via Get-MgDeviceManagementManagedDevice -All.
      3. Enumerates escrowed BitLocker recovery key records via
         Get-MgInformationProtectionBitlockerRecoveryKey -All (Entra ID escrow, metadata only —
         this does NOT retrieve the actual recovery key value, by design; see BitLockerKey.ReadBasic.All
         below).
      4. Cross-references the two: for every device reporting itself as encrypted, does a matching
         BitLocker recovery key object exist in Entra ID for that device?

      RED   = device reports encrypted, but no BitLocker recovery key record found in Entra ID.
              This is a DATA-LOSS RISK, not a warning.
      GREEN = device reports encrypted and has at least one escrowed key record in Entra ID.

    A NOTE ON THE "IsEncrypted" PROPERTY: the managedDevice object returned by
    Get-MgDeviceManagementManagedDevice is widely documented as exposing an IsEncrypted boolean,
    but property surfaces on this resource type have shifted between Microsoft Graph PowerShell
    SDK releases and API versions. This script does NOT assume that property exists — it checks
    for it at runtime on the first returned device and throws a clear, loud warning (not a silent
    skip) if it can't find it, so you can confirm the correct property name for your installed
    module version (Get-MgDeviceManagementManagedDevice -All | Get-Member) rather than silently
    trusting a guessed name.

.NOTES
    Author:   Imran Awan
    Blog:     https://endpointweekly.com/blog/bitlocker-recovery-key-escrow-audit-intune-entra.html
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement modules.
              Get-MgInformationProtectionBitlockerRecoveryKey may only be available under the
              Microsoft.Graph.Beta module (Microsoft.Graph.Beta.Identity.SignIns) depending on your
              installed SDK version and whether this endpoint has been promoted to v1.0 in your
              tenant — confirm with Get-Command Get-MgInformationProtectionBitlockerRecoveryKey
              before relying on the v1.0 module name in production.
    Graph scopes required:
              BitLockerKey.ReadBasic.All (metadata only - does NOT expose the recovery key value.
                                          Do not request BitLockerKey.Read.All for this reporting
                                          use case; that scope exposes the actual key value and is
                                          a higher privilege than a read-only audit needs.)
              DeviceManagementManagedDevices.Read.All
              Device.Read.All
    Auth:     Supports BOTH app-only certificate auth (-TenantId/-ClientId/-CertificateThumbprint)
              and interactive device-code sign-in (no params, or explicit -Interactive). Every run
              connects fresh — this script does not reuse a cached Graph session.
    Tested:   Validate on a pilot group in your tenant and manually cross-check flagged devices
              against the Entra admin center (Devices > All devices > <device> > BitLocker keys)
              before trusting the fleet-wide output. See the blog post above for that manual check.

.PARAMETER TenantId
    Tenant ID (GUID or verified domain) to connect to. Required for app-only certificate auth.

.PARAMETER ClientId
    App registration (client) ID to use for app-only certificate auth.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (installed in the local certificate store) to use for app-only
    authentication. When -TenantId, -ClientId and -CertificateThumbprint are all supplied, the
    script connects non-interactively. Otherwise it falls back to interactive device-code sign-in.

.PARAMETER Interactive
    Force interactive device-code sign-in even if app-only parameters are supplied.

.PARAMETER ExportCsv
    Optional path to export the full compliance report as CSV, e.g. C:\Reports\bitlocker-escrow.csv

.EXAMPLE
    .\Get-BitLockerEscrowComplianceReport.ps1

    Runs interactively (device-code sign-in), prints a colour-coded console report.

.EXAMPLE
    .\Get-BitLockerEscrowComplianceReport.ps1 -ExportCsv "C:\Reports\bitlocker-escrow-$(Get-Date -Format 'yyyyMMdd').csv"

    Runs interactively and exports the full results to a dated CSV for a compliance record.

.EXAMPLE
    .\Get-BitLockerEscrowComplianceReport.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "AB12CD34EF56..." -ExportCsv "C:\Reports\bitlocker-escrow.csv"

    Runs unattended using app-only certificate authentication — suitable for a scheduled task.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [switch]$Interactive,
    [string]$ExportCsv
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 1. Connect to Microsoft Graph — always fresh, never reuse a cached session.
#    App-only certificate auth if all three params are supplied and -Interactive
#    was not forced; otherwise fall back to interactive device-code sign-in.
# ---------------------------------------------------------------------------
Write-Section "Connecting to Microsoft Graph"

$requiredScopes = @(
    "BitLockerKey.ReadBasic.All",
    "DeviceManagementManagedDevices.Read.All",
    "Device.Read.All"
)

try {
    # Disconnect any lingering session so every run starts clean.
    Get-MgContext -ErrorAction SilentlyContinue | Out-Null
    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }

    $useAppOnly = ($TenantId -and $ClientId -and $CertificateThumbprint -and -not $Interactive)

    if ($useAppOnly) {
        Write-Host "Connecting with app-only certificate authentication..." -ForegroundColor Gray
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host "Connecting with interactive device-code sign-in..." -ForegroundColor Gray
        $connectParams = @{
            Scopes           = $requiredScopes
            NoWelcome        = $true
            UseDeviceCode    = $true
            ErrorAction      = 'Stop'
        }
        if ($TenantId) { $connectParams['TenantId'] = $TenantId }
        Connect-MgGraph @connectParams
    }
}
catch {
    Write-Host "FATAL: Failed to connect to Microsoft Graph — $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$context = Get-MgContext
if (-not $context) {
    Write-Host "FATAL: Connect-MgGraph completed but no Graph context is present. Aborting rather than reporting a false 'zero non-compliant devices' result." -ForegroundColor Red
    exit 1
}
Write-Host "Connected as $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Enumerate managed Windows devices and escrowed BitLocker recovery keys.
#    Any Graph query failure here is fatal — we never want to silently report
#    "0 non-compliant devices" because a query actually failed.
# ---------------------------------------------------------------------------
Write-Section "Enumerating managed Windows devices"

try {
    Write-Host "Pulling Intune managed device list (Get-MgDeviceManagementManagedDevice -All)..." -ForegroundColor Gray
    $managedDevices = Get-MgDeviceManagementManagedDevice -All -Filter "operatingSystem eq 'Windows'" -ErrorAction Stop
}
catch {
    Write-Host "FATAL: Get-MgDeviceManagementManagedDevice failed — $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (-not $managedDevices) {
    Write-Host "FATAL: Get-MgDeviceManagementManagedDevice returned no data at all — treating this as a query failure, not '0 devices in tenant'. Verify permissions and connectivity." -ForegroundColor Red
    exit 1
}

# Defensive check: confirm the IsEncrypted property actually exists on the returned object
# before trusting it anywhere below. Do not assume the property name silently.
$sampleDevice = $managedDevices | Select-Object -First 1
if (-not ($sampleDevice.PSObject.Properties.Name -contains 'IsEncrypted')) {
    Write-Host "WARNING: 'IsEncrypted' property was not found on the managedDevice object returned by your installed Graph module version." -ForegroundColor Yellow
    Write-Host "         Run 'Get-MgDeviceManagementManagedDevice -All | Get-Member' to confirm the correct property name for encryption state" -ForegroundColor Yellow
    Write-Host "         on your schema before trusting this report. Aborting rather than guessing." -ForegroundColor Yellow
    exit 1
}

try {
    Write-Host "Pulling Entra ID BitLocker recovery key records (Get-MgInformationProtectionBitlockerRecoveryKey -All)..." -ForegroundColor Gray
    $allKeys = Get-MgInformationProtectionBitlockerRecoveryKey -All -ErrorAction Stop
}
catch {
    Write-Host "FATAL: Get-MgInformationProtectionBitlockerRecoveryKey failed — $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       If this cmdlet is not recognised, confirm whether it's exposed under the Microsoft.Graph.Beta module" -ForegroundColor Red
    Write-Host "       in your tenant/module version rather than the v1.0 module (Get-Command Get-MgInformationProtectionBitlockerRecoveryKey)." -ForegroundColor Red
    exit 1
}

# Index recovery key records by DeviceId for fast lookup. An empty result set here is legal
# (a genuinely brand-new tenant might have none), but it should never be silently mistaken for
# "every device is compliant" — the per-device loop below still enforces that correctly.
$keysByDevice = @{}
if ($allKeys) {
    foreach ($k in $allKeys) {
        if ($k.DeviceId) {
            if (-not $keysByDevice.ContainsKey($k.DeviceId)) {
                $keysByDevice[$k.DeviceId] = New-Object System.Collections.Generic.List[object]
            }
            $keysByDevice[$k.DeviceId].Add($k)
        }
    }
}

Write-Host "Found $($managedDevices.Count) Windows managed devices, $($allKeys.Count) escrowed recovery key records." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 3. Evaluate escrow compliance for every encrypted device.
# ---------------------------------------------------------------------------
Write-Section "Evaluating escrow compliance"

$results = New-Object System.Collections.Generic.List[object]

foreach ($device in $managedDevices) {

    # Only devices reporting encryption are in scope for an escrow audit — an unencrypted
    # device is a separate (encryption-coverage) problem, not an escrow-gap problem.
    if ($device.IsEncrypted -ne $true) { continue }

    $deviceName    = $device.DeviceName
    $aadDeviceId   = $device.AzureAdDeviceId
    $matchingKeys  = if ($aadDeviceId -and $keysByDevice.ContainsKey($aadDeviceId)) { $keysByDevice[$aadDeviceId] } else { $null }

    if (-not $matchingKeys -or $matchingKeys.Count -eq 0) {
        $status = 'RED'
        $reason = 'No BitLocker key found in Entra ID'
    }
    else {
        $latestKey = $matchingKeys | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 1
        $status = 'GREEN'
        $reason = "Key escrowed $($latestKey.CreatedDateTime.ToString('yyyy-MM-dd'))"
    }

    $results.Add([PSCustomObject]@{
        DeviceName      = $deviceName
        AzureAdDeviceId = $aadDeviceId
        IsEncrypted     = $device.IsEncrypted
        Status          = $status
        Reason          = $reason
        KeyCount        = if ($matchingKeys) { $matchingKeys.Count } else { 0 }
        LastKeyCreated  = if ($matchingKeys) { ($matchingKeys | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime } else { $null }
    })
}

# ---------------------------------------------------------------------------
# 4. Print the colour-coded console report.
# ---------------------------------------------------------------------------
Write-Section "BitLocker escrow compliance report"

foreach ($r in ($results | Sort-Object -Property Status, DeviceName)) {
    switch ($r.Status) {
        'RED' {
            Write-Host ("[FAIL]  {0,-22} Encrypted=True  |  {1}  |  DATA-LOSS RISK" -f $r.DeviceName, $r.Reason) -ForegroundColor Red
        }
        'GREEN' {
            Write-Host ("[OK]    {0,-22} Encrypted=True  |  {1}" -f $r.DeviceName, $r.Reason) -ForegroundColor Green
        }
        default {
            Write-Host ("[?]     {0,-22} status unknown" -f $r.DeviceName) -ForegroundColor DarkGray
        }
    }
}

$greenCount = ($results | Where-Object Status -eq 'GREEN').Count
$redCount   = ($results | Where-Object Status -eq 'RED').Count

Write-Host ""
Write-Host "Summary: $greenCount GREEN | $redCount RED (out of $($results.Count) encrypted devices checked)" -ForegroundColor Cyan

if ($redCount -gt 0) {
    Write-Host ""
    Write-Host "ACTION NEEDED: $redCount device(s) are encrypted with NO recoverable key on record in Entra ID." -ForegroundColor Red
}

Write-Host "REMINDER: this run checked Entra ID escrow only. Hybrid-joined devices escrowing to on-prem AD are NOT covered by this script - see the separate msFVE-RecoveryInformation query in the script header." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# 5. Optional CSV export.
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    try {
        $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "CSV exported: $ExportCsv" -ForegroundColor Gray
    }
    catch {
        Write-Host "WARNING: Failed to export CSV to $ExportCsv — $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
