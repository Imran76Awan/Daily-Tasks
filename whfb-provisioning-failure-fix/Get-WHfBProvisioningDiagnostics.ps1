<#
.SYNOPSIS
    Runs a full local diagnostic pass on THIS device to find why Windows Hello for
    Business (WHfB) provisioning is failing, and prints a plain-English verdict.

.DESCRIPTION
    Everything here checks the local machine, not the cloud tenant. It pulls the
    device join state, TPM health, the WHfB provisioning events from the dedicated
    "User Device Registration" event log, MDM enrollment state, and the
    PassportForWork policy registry — then maps what it finds to the specific
    failure it points to (matching the Event IDs and error codes described in the
    EndpointWeekly WHfB provisioning failure guide).

    Run this AS THE AFFECTED USER (not SYSTEM, not a different admin account) so the
    PRT and WHfB key state reflect the user actually having the problem. Run
    PowerShell as Administrator so the Event Viewer, TPM and registry checks all
    succeed.

    READ-ONLY — this script only reads state. It does not change any policy,
    registry value, TPM state, or WHfB configuration.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/whfb-provisioning-failure-fix.html
    Requires:    Windows 10 1703+ / Windows 11, run as Administrator
    Run as:      The affected user's own logon session (not SYSTEM, not an admin
                 impersonating the user) — PRT and WHfB key state are per-user.
    Version:     1.0
    Date:        2026-07-23

.PARAMETER OutputPath
    Where to write the full text report. Defaults to a timestamped file in
    %TEMP%.

.PARAMETER HoursBack
    How far back to search the User Device Registration event log. Defaults to 48
    hours — widen this if the last failed logon was further back.

.EXAMPLE
    .\Get-WHfBProvisioningDiagnostics.ps1
    Runs the full diagnostic and prints a colour-coded verdict to the console.

.EXAMPLE
    .\Get-WHfBProvisioningDiagnostics.ps1 -HoursBack 168 -OutputPath C:\Temp\whfb-report.txt
    Looks back 7 days and saves the report to a specific path.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:TEMP\WHfB-Diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmm').txt",
    [int]$HoursBack = 48
)

$ErrorActionPreference = 'Continue'
$report      = [System.Collections.Generic.List[string]]::new()
$verdict     = [System.Collections.Generic.List[string]]::new()
$script:failCount = 0
$script:warnCount = 0

function Add-Line { param($t=''); $report.Add($t) }
function Add-Verdict { param([string]$Level, [string]$Text)
    $color = switch ($Level) { 'PASS' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'White'} }
    Write-Host "  [$Level] $Text" -ForegroundColor $color
    $verdict.Add("[$Level] $Text")
    if ($Level -eq 'FAIL') { $script:failCount++ }
    if ($Level -eq 'WARN') { $script:warnCount++ }
}

Add-Line "=== WHfB Provisioning Diagnostic Report ==="
Add-Line "Generated: $(Get-Date)"
Add-Line "Computer:  $env:COMPUTERNAME"
Add-Line "User:      $env:USERNAME"
Add-Line ""

Write-Host "`n=== WHfB Provisioning Diagnostics ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME  |  User: $env:USERNAME`n" -ForegroundColor Cyan

# ── Section 1: Device join state (dsregcmd /status) ────────────────────────────
Write-Host "[1/7] Device join state (dsregcmd /status)..." -ForegroundColor Cyan
Add-Line "--- DEVICE JOIN STATE ---"
$dsreg = dsregcmd /status
$joinLines = $dsreg | Select-String -Pattern "AzureAdJoined|WorkplaceJoined|DomainJoined|AzureAdPrt|PrtUpdateTime|PrtExpiryTime|OnPremTgt|AzureAdTgt|NgcSet|NgcKeyId|TenantName|DeviceId"
$joinLines | ForEach-Object { Add-Line $_.Line.Trim() }

$aadJoined = ($dsreg | Select-String "AzureAdJoined\s*:\s*YES") -ne $null
$hybridJoined = ($dsreg | Select-String "DomainJoined\s*:\s*YES") -ne $null
$aadPrt = ($dsreg | Select-String "AzureAdPrt\s*:\s*YES") -ne $null
$ngcSet = ($dsreg | Select-String "NgcSet\s*:\s*YES") -ne $null

if ($aadJoined -or $hybridJoined) { Add-Verdict PASS "Device is Entra joined or Hybrid Entra joined" }
else { Add-Verdict FAIL "Device is NOT Entra joined or Hybrid joined — WHfB cannot provision. This alone will produce Event ID 360 with error 0x801C0003." }

if ($aadPrt) { Add-Verdict PASS "User has a valid Primary Refresh Token (PRT)" }
else { Add-Verdict FAIL "No PRT for this user — provisioning WILL fail with Event ID 362 (Enterprise STS authentication failed). Sign out/in with Entra credentials, check network path to login.microsoftonline.com." }

if ($ngcSet) { Add-Verdict PASS "WHfB key (NGC) is already provisioned on this device (NgcSet: YES)" }
else { Add-Verdict WARN "WHfB key not yet provisioned (NgcSet: NO or missing) — expected if setup hasn't completed yet" }

# ── Section 2: TPM state ────────────────────────────────────────────────────────
Write-Host "[2/7] TPM state..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- TPM STATE ---"
try {
    $tpm = Get-Tpm
    Add-Line "Present:  $($tpm.TpmPresent)"
    Add-Line "Ready:    $($tpm.TpmReady)"
    Add-Line "Enabled:  $($tpm.TpmEnabled)"
    Add-Line "Owned:    $($tpm.TpmOwned)"
    Add-Line "Lockout:  $($tpm.LockoutCount) attempts"
    try {
        $tpmWmi = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction Stop
        Add-Line "Spec Ver: $($tpmWmi.SpecVersion)"
        $tpmVer = $tpmWmi.SpecVersion
    } catch { Add-Line "Spec Ver: could not read (WMI error)"; $tpmVer = $null }

    if ($tpm.TpmPresent -and $tpm.TpmReady) { Add-Verdict PASS "TPM present and ready" }
    else { Add-Verdict FAIL "TPM missing or not ready — WHfB cannot create its key without a working TPM. Check Device Manager > Security devices and firmware TPM settings." }

    if ($tpmVer -and $tpmVer -notlike '2.0*') {
        Add-Verdict WARN "TPM spec version is $tpmVer, not 2.0 — TPM 1.2 does not support attestation, so Cloud Trust / Certificate Trust key attestation will fail. Key Trust (non-attested) can still work."
    }
    if ($tpm.LockoutCount -gt 0) {
        Add-Verdict WARN "TPM has $($tpm.LockoutCount) recorded lockout attempt(s) — check System log for Event ID 1026 (source TPM-WMI). Repeated PIN failures can put the TPM into a cooldown that silently blocks key creation."
    }
} catch {
    Add-Line "Could not query TPM: $($_.Exception.Message)"
    Add-Verdict FAIL "Get-Tpm failed — run PowerShell as Administrator, or the TPM module is unavailable on this device."
}

# ── Section 3: WHfB provisioning events (User Device Registration/Admin) ───────
Write-Host "[3/7] WHfB provisioning events (last $HoursBack h)..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- USER DEVICE REGISTRATION EVENTS (last $HoursBack h) ---"

$eventMeaning = @{
    358 = 'Provisioning will be launched — all prerequisites met'
    360 = 'Provisioning will NOT be launched — one or more prerequisites not met at logon'
    362 = 'Enterprise STS authentication failed — no PRT, no DC connectivity, or token issuance failure'
    363 = 'Passport key missing or attestation failed — TPM not ready, key creation failed, or attestation endpoint unreachable'
    304 = 'Automatic device join failed — hybrid join prerequisites not met, or SCP misconfigured'
    300 = 'Device registration completed successfully — healthy baseline'
}

$events = Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-$HoursBack) }

if (-not $events) {
    Add-Line "No events found in the last $HoursBack hours. Widen -HoursBack if the failure was earlier."
    Add-Verdict WARN "No WHfB provisioning events found in the requested window — try a larger -HoursBack value covering the last failed logon."
} else {
    foreach ($e in ($events | Sort-Object TimeCreated -Descending)) {
        $meaning = $eventMeaning[[int]$e.Id]
        $firstLine = $e.Message.Split("`n")[0]
        Add-Line "[$($e.TimeCreated)] ID $($e.Id) [$($e.LevelDisplayName)] $firstLine"
        if ($meaning) { Add-Line "    -> $meaning" }
    }

    $has360 = $events | Where-Object Id -eq 360 | Select-Object -First 1
    $has362 = $events | Where-Object Id -eq 362 | Select-Object -First 1
    $has363 = $events | Where-Object Id -eq 363 | Select-Object -First 1
    $has304 = $events | Where-Object Id -eq 304 | Select-Object -First 1
    $has358 = $events | Where-Object Id -eq 358 | Select-Object -First 1
    $has300 = $events | Where-Object Id -eq 300 | Select-Object -First 1

    if ($has360) {
        $msg = ($has360.Message -split "`n")[0]
        Add-Verdict FAIL "Event 360 found — provisioning was blocked before it started. Read the full event description for the error code: 0x801C0003 = not Entra joined, 0x801C044D = not logged on with Entra creds, 0x801C03F2 = WHfB policy not configured. First line: $msg"
    }
    if ($has362) { Add-Verdict FAIL "Event 362 found — Enterprise STS auth failed. This lines up with the PRT check above; fix the PRT/connectivity issue first." }
    if ($has363) { Add-Verdict FAIL "Event 363 found — Passport key/attestation failed. This lines up with the TPM check above." }
    if ($has304) { Add-Verdict WARN "Event 304 found — automatic device join failed. Check Hybrid Join prerequisites / SCP configuration." }
    if ($has358 -and -not $has360) { Add-Verdict PASS "Event 358 found (provisioning launched) with no blocking 360 — prerequisites were met at that logon." }
    if ($has300) { Add-Verdict PASS "Event 300 found — device registration completed successfully at least once." }
    if (-not ($has360 -or $has362 -or $has363 -or $has304)) {
        Add-Verdict PASS "No blocking WHfB error events (360/362/363/304) found in this window."
    }
}

# ── Section 4: TPM dictionary-attack lockout (System log, Event 1026) ──────────
Write-Host "[4/7] TPM lockout events (System log)..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- TPM LOCKOUT EVENTS (System log, last $HoursBack h) ---"
$tpmLockoutEvents = $null
try {
    $tpmLockoutEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1026; ProviderName='TPM-WMI'} -MaxEvents 20 -ErrorAction Stop |
        Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-$HoursBack) }
} catch {
    # No matching events, or the TPM-WMI provider/event source isn't present on this device — treat as "none found"
    $tpmLockoutEvents = $null
}
if ($tpmLockoutEvents) {
    $tpmLockoutEvents | ForEach-Object { Add-Line "[$($_.TimeCreated)] $($_.Message.Split("`n")[0])" }
    Add-Verdict WARN "TPM-WMI Event 1026 found — 'TPM hardware cannot be provisioned automatically'. The TPM is in a dictionary-attack lockout cooldown. Do NOT clear the TPM without confirming BitLocker recovery key escrow first — clearing destroys all TPM-protected keys."
} else {
    Add-Line "None found."
}

# ── Section 5: MDM enrollment ────────────────────────────────────────────────────
Write-Host "[5/7] MDM enrollment state..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- MDM ENROLLMENT ---"
$mdm = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.EnrollmentType -ne $null }
if ($mdm) {
    $mdm | ForEach-Object { Add-Line "Enrollment: $($_.ProviderID) | Type: $($_.EnrollmentType) | UPN: $($_.UPN)" }
    Add-Verdict PASS "Device has at least one active MDM enrollment record"
} else {
    Add-Line "No MDM enrollment records found."
    Add-Verdict FAIL "No MDM enrollment found — if you expect Intune to deliver the WHfB policy, the device isn't enrolled (or the enrollment is broken). Check Settings > Accounts > Access work or school."
}

# ── Section 6: PassportForWork policy registry ──────────────────────────────────
Write-Host "[6/7] PassportForWork policy (WHfB CSP)..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- PASSPORTFORWORK POLICY REGISTRY ---"
$pfwPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\PassportForWork"
if (Test-Path $pfwPath) {
    $pfw = Get-ItemProperty $pfwPath
    $pfw.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        Add-Line "  $($_.Name) = $($_.Value)"
    }
    Add-Verdict PASS "PassportForWork policy key found — WHfB policy has been applied to this device"

    $useCertOnPrem  = ($pfw.PSObject.Properties | Where-Object Name -eq 'UseCertificateForOnPremAuth').Value
    $useCloudTrust  = ($pfw.PSObject.Properties | Where-Object Name -eq 'UseCloudTrustForOnPremAuth').Value
    if ($useCertOnPrem -eq 1 -and $useCloudTrust -eq 1) {
        Add-Verdict FAIL "Policy conflict: 'Use certificate for on-premises authentication' AND 'Use cloud trust for on-premises authentication' are BOTH enabled. Cloud Trust deployments must set certificate-based on-prem auth to Disabled — this conflicts with the Cloud Trust Kerberos ticket flow."
    }
} else {
    Add-Line "PassportForWork policy key NOT FOUND."
    Add-Verdict FAIL "PassportForWork policy key is missing — WHfB policy has not reached this device. Check the Intune Account Protection profile (or Settings Catalog PassportForWork CSP) is deployed and assigned to this device/user, with no conflicting deprecated Identity Protection profile still assigned."
}

# ── Section 7: Windows version ──────────────────────────────────────────────────
Write-Host "[7/7] Windows version..." -ForegroundColor Cyan
Add-Line ""; Add-Line "--- WINDOWS VERSION ---"
$os = [System.Environment]::OSVersion
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
Add-Line "Version: $($os.Version)  Build: $build"
if ([int]$build -ge 15063) { Add-Verdict PASS "Windows build $build meets the WHfB minimum (1703 / build 15063+)" }
else { Add-Verdict FAIL "Windows build $build is below the WHfB minimum supported build (1703 / 15063) for cloud or hybrid deployment." }

# ── Summary ──────────────────────────────────────────────────────────────────────
Add-Line ""; Add-Line "--- VERDICT SUMMARY ---"
$verdict | ForEach-Object { Add-Line $_ }

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "FAIL: $script:failCount   WARN: $script:warnCount" -ForegroundColor $(if ($script:failCount -gt 0) { 'Red' } elseif ($script:warnCount -gt 0) { 'Yellow' } else { 'Green' })
if ($script:failCount -eq 0 -and $script:warnCount -eq 0) {
    Write-Host "No blocking issues found. If WHfB still isn't set up, sign out and sign back in to trigger provisioning — it only re-evaluates at logon." -ForegroundColor Green
}

$report | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nFull report saved to: $OutputPath" -ForegroundColor Cyan
