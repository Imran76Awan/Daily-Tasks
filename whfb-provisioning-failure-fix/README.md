# WHfB Provisioning Failure — Local Diagnostics

Local, on-device PowerShell for diagnosing why Windows Hello for Business (WHfB)
provisioning is failing on a specific laptop — companion scripts for the
EndpointWeekly post:
**[Windows Hello for Business Provisioning Failure: Fix Event ID 360, TPM Issues & Certificate Errors](https://endpointweekly.com/blog/whfb-provisioning-failure-fix.html)**

Unlike the tenant-wide Entra audits in this repo, these scripts run **on the
affected device** and check local state: Event Viewer, TPM, `dsregcmd /status`,
MDM enrollment, and the WHfB policy registry.

## Scripts

| Script | What it does |
|--------|--------------|
| `Get-WHfBProvisioningDiagnostics.ps1` | **Read-only.** Checks device join state, TPM health, WHfB provisioning events (358/360/362/363/304/300), TPM lockout events (1026), MDM enrollment, and the PassportForWork policy registry. Prints a colour-coded PASS/FAIL/WARN verdict explaining exactly what's broken, and saves a full text report. |
| `Reset-WHfBTpmLockout.ps1` | Checks TPM dictionary-attack lockout status. **Reports only by default — changes nothing.** Only resets the lockout counter if you pass `-Force`, and warns clearly about the difference between resetting the lockout counter (safe) and clearing the TPM (destroys BitLocker/WHfB keys). |

## Requirements

- Windows 10 1703+ or Windows 11
- Run PowerShell **as Administrator** (for Event Viewer, TPM, and registry access)
- Run **as the affected user's own logon session** — PRT and WHfB key state (`AzureAdPrt`, `NgcSet`) are per-user, not per-machine

## Usage

```powershell
# Full diagnostic — read-only, safe to run any time
.\Get-WHfBProvisioningDiagnostics.ps1

# Look back further than the default 48 hours if the failed logon was earlier
.\Get-WHfBProvisioningDiagnostics.ps1 -HoursBack 168

# Check TPM lockout status only (no changes)
.\Reset-WHfBTpmLockout.ps1

# Actually reset the TPM lockout counter (only after reading the warnings)
.\Reset-WHfBTpmLockout.ps1 -Force
```

## How to read the verdict

Each check prints `[PASS]`, `[WARN]`, or `[FAIL]` with a plain-English explanation
tied to the exact Event ID or setting that's causing it — for example:

```
[FAIL] Event 362 found — Enterprise STS auth failed. This lines up with the
       PRT check above; fix the PRT/connectivity issue first.
```

Work through `[FAIL]` items first, then `[WARN]` items. A clean run with zero
FAIL/WARN and no WHfB key yet just means: sign out and sign back in — WHfB
provisioning only re-evaluates at logon.

## Safety

`Get-WHfBProvisioningDiagnostics.ps1` is fully read-only. `Reset-WHfBTpmLockout.ps1`
makes no changes unless you explicitly pass `-Force`, and even then it only resets
the lockout counter — it does not clear the TPM.
