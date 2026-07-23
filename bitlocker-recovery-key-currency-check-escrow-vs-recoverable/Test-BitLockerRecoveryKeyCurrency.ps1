<#
.SYNOPSIS
    Checks whether the BitLocker recovery key escrowed to Microsoft Entra ID for
    this device is actually the CURRENT key protector, not a stale one left over
    from a re-image, protector rotation, or TPM reset.

.DESCRIPTION
    An escrow audit that only checks "does a key record exist in Entra ID" can
    still report a device as compliant years after that record went stale. A
    BitLocker recovery key is tied to a specific key protector, identified by its
    own KeyProtectorId GUID. Re-imaging a device, rotating protectors, resetting
    the TPM, or replacing the drive all mint a brand-new KeyProtectorId locally -
    but nothing automatically removes or updates the old escrowed record in Entra
    ID. The result: an existence-only audit reports GREEN for a device whose
    escrowed key would not actually recover it.

    This script compares the live local KeyProtectorId for the RecoveryPassword
    protector (from Get-BitLockerVolume) against the escrowed records Microsoft
    Graph has on file for this device's Entra ID device ID, and reports whether
    the record on file is current, stale, or missing entirely.

    This script is read-only. It makes no changes to BitLocker, Intune, or Entra
    ID, and it does not read or display the actual recovery key value - only key
    protector IDs, which are not secrets.

.PARAMETER MountPoint
    The drive letter to check. Defaults to "C:".

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive
    device-code sign-in instead.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only certificate authentication. Requires the
    app registration to have BitlockerKey.ReadBasic.All granted as an Application
    permission with admin consent.

.NOTES
    Blog post: https://endpointweekly.com/blog/bitlocker-recovery-key-currency-check-escrow-vs-recoverable.html
    Author:    Imran Awan
    Version:   1.0

    Microsoft's own reference pages for Get-BitLockerVolume and the Graph
    bitlockerRecoveryKey resource do not explicitly state that the Graph
    bitlockerRecoveryKey.id is guaranteed to equal the local KeyProtectorId GUID
    in every case. BackupToAAD-BitLockerKeyProtector backs a protector up BY its
    KeyProtectorId, so a match is the expected normal outcome - but this script
    treats a non-match as "needs manual review" rather than asserting it proves
    the key is definitely unrecoverable.

.EXAMPLE
    .\Test-BitLockerRecoveryKeyCurrency.ps1
    Checks drive C: on the local device, interactive device-code sign-in.

.EXAMPLE
    .\Test-BitLockerRecoveryKeyCurrency.ps1 -MountPoint "D:" -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx"
    Checks drive D:, app-only certificate authentication, no interactive sign-in required.
#>

[CmdletBinding()]
param (
    [string]$MountPoint = "C:",
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

function Get-NormalizedGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return ($Value -replace '[{}]', '').Trim().ToLowerInvariant()
}

#region 1. Local BitLocker state
Write-Host "`n[1] Reading local BitLocker key protectors for $MountPoint..." -ForegroundColor Cyan
try {
    $volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
} catch {
    Write-Host "Failed to query BitLocker volume $MountPoint : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($volume.ProtectionStatus -ne 'On') {
    Write-Host "  BitLocker protection is NOT ON for $MountPoint (status: $($volume.ProtectionStatus))." -ForegroundColor Yellow
    Write-Host "  Nothing to check - this volume is not currently protected." -ForegroundColor Yellow
    exit 1
}

$recoveryProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
if (-not $recoveryProtector) {
    Write-Host "  No RecoveryPassword key protector found on $MountPoint." -ForegroundColor Red
    Write-Host "  This volume has no recovery key protector at all - escrow currency is irrelevant, there is nothing to escrow." -ForegroundColor Red
    exit 1
}

$localKeyId = Get-NormalizedGuid $recoveryProtector.KeyProtectorId
Write-Host "  Local RecoveryPassword KeyProtectorId: $localKeyId" -ForegroundColor Green
#endregion

#region 2. Local Entra ID device identity
Write-Host "`n[2] Resolving this device's Microsoft Entra device ID..." -ForegroundColor Cyan
try {
    $dsregOutput = dsregcmd /status
} catch {
    Write-Host "Failed to run dsregcmd /status: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
$deviceIdLine = $dsregOutput | Select-String -Pattern 'DeviceId\s*:\s*(\S+)'
if (-not $deviceIdLine) {
    Write-Host "  Could not find a DeviceId in dsregcmd /status output. Is this device Entra joined or hybrid joined?" -ForegroundColor Red
    exit 1
}
$entraDeviceId = ($deviceIdLine.Line -split ':', 2)[1].Trim()
Write-Host "  Entra device ID: $entraDeviceId" -ForegroundColor Green
#endregion

#region 3. Connect to Microsoft Graph
Write-Host "`n[3] Connecting to Microsoft Graph..." -ForegroundColor Cyan
$requiredModules = @('Microsoft.Graph.Identity.SignIns')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing $mod module..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force
    }
    Import-Module $mod -ErrorAction Stop
}

$useAppOnlyAuth = $TenantId -and $ClientId -and $CertificateThumbprint
try {
    if ($useAppOnlyAuth) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes "BitlockerKey.ReadBasic.All" -UseDeviceCode -ErrorAction Stop
    }
} catch {
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region 4. Escrowed records for this device
Write-Host "`n[4] Retrieving escrowed BitLocker recovery keys for this device from Entra ID..." -ForegroundColor Cyan
try {
    $escrowedKeys = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$entraDeviceId'" -All -ErrorAction Stop
} catch {
    Write-Host "Failed to query escrowed recovery keys: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n============================================================" -ForegroundColor White
Write-Host " BITLOCKER RECOVERY KEY CURRENCY CHECK - $MountPoint" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

if (-not $escrowedKeys -or $escrowedKeys.Count -eq 0) {
    Write-Host "  NO ESCROWED RECORDS FOUND for this device in Entra ID." -ForegroundColor Red
    Write-Host "  The local recovery key is not escrowed anywhere Graph can see. Re-escrow immediately:" -ForegroundColor Red
    Write-Host "  BackupToAAD-BitLockerKeyProtector -MountPoint `"$MountPoint`" -KeyProtectorId `"$($recoveryProtector.KeyProtectorId)`"" -ForegroundColor Yellow
    exit 1
}

Write-Host "  Found $($escrowedKeys.Count) escrowed record(s) for this device." -ForegroundColor Cyan
$match = $escrowedKeys | Where-Object { (Get-NormalizedGuid $_.Id) -eq $localKeyId } | Select-Object -First 1

if ($match) {
    Write-Host "`n  CURRENT - the escrowed record on file matches the live local key protector." -ForegroundColor Green
    Write-Host "  Escrowed record ID  : $($match.Id)"
    Write-Host "  Created             : $($match.CreatedDateTime)"
    exit 0
} else {
    Write-Host "`n  STALE - escrowed record(s) exist, but none match the current local KeyProtectorId." -ForegroundColor Red
    Write-Host "  Local KeyProtectorId : $localKeyId"
    foreach ($k in $escrowedKeys) {
        Write-Host "  Escrowed record      : $($k.Id)  (created $($k.CreatedDateTime))"
    }
    Write-Host "`n  This device's escrowed key record is out of date. Re-escrow the current protector:" -ForegroundColor Yellow
    Write-Host "  BackupToAAD-BitLockerKeyProtector -MountPoint `"$MountPoint`" -KeyProtectorId `"$($recoveryProtector.KeyProtectorId)`"" -ForegroundColor Yellow
    Write-Host "`n  Note: this confirms the record on file is not current. It does not, by itself, prove the record" -ForegroundColor Cyan
    Write-Host "  would fail to decrypt the volume - Microsoft's docs do not explicitly guarantee the ID mapping in" -ForegroundColor Cyan
    Write-Host "  every case. Treat STALE as 'needs manual review and re-escrow', not an automatic hard failure." -ForegroundColor Cyan
    exit 1
}
#endregion
