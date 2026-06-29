# Secure Boot Certificate Update — Intune Proactive Remediation Scripts

Scripts to detect and remediate the two Secure Boot failure states visible in the Intune Secure Boot Status Report.

## Background

Microsoft's 2011 Secure Boot certificates expire in 2026. Devices that do not receive updated DB and KEK certificates (2023 versions) will progressively lose boot-level security protections. The Intune Secure Boot Status Report surfaces two distinct failure states:

| State | Meaning | Script folder |
|-------|---------|---------------|
| **Not Up to Date** | Secure Boot enabled but still on expiring 2011 certificates | `Not_Up_to_Date_Secure Boot/` |
| **Not Applicable** | Secure Boot disabled — device cannot receive certificate updates | `Non_Applicable_SecureBoot/` |

---

## Folder 1 — `Not_Up_to_Date_Secure Boot/`

Targets devices where Secure Boot is **enabled** but the 2023 UEFI CA certificate update has not been applied.

### Scripts

| File | Purpose |
|------|---------|
| `Check Secure Boot CA 2023 certificate update_D.ps1` | **Detection** — exits 0 (compliant) or 1 (non-compliant) |
| `Trigger Secure Boot CA 2023 certificate update.ps1` | **Remediation** — sets registry trigger and starts the update task |

### How it works

**Detection logic:**
1. Confirms Secure Boot is enabled via `Confirm-SecureBootUEFI`
2. Reads `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\UEFICA2023Status`
3. Returns compliant if status is `Updated` (Capable=2) or `InProgress`
4. Returns non-compliant if status is `NotStarted` and the `AvailableUpdates` trigger is not set

**Remediation logic:**
1. Confirms Secure Boot is enabled
2. If status is `NotStarted` and trigger not set: writes `AvailableUpdates = 0x5944` to registry
3. Starts the `\Microsoft\Windows\PI\Secure-Boot-Update` scheduled task
4. A reboot is required to complete the update

### Registry paths

```
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\UEFICA2023Status
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\WindowsUEFICA2023Capable
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates
```

### Intune deployment

1. Intune admin centre → **Devices** → **Scripts and remediations** → **Create**
2. Name: `Secure Boot CA 2023 Certificate Update`
3. Detection script: `Check Secure Boot CA 2023 certificate update_D.ps1`
4. Remediation script: `Trigger Secure Boot CA 2023 certificate update.ps1`
5. Run as: **System** (64-bit)
6. Assign to: device group containing "Not Up to Date" devices from the Secure Boot Status Report

---

## Folder 2 — `Non_Applicable_SecureBoot/`

Targets **Lenovo** devices where Secure Boot is **disabled** in BIOS. Uses Lenovo's WMI interface to detect and enable Secure Boot remotely via Intune.

### Scripts

| File | Purpose |
|------|---------|
| `Detect-LenovoSecureBoot.ps1` | **Detection** — exits 0 if Secure Boot enabled, 1 if disabled |
| `Remediate-LenovoSecureBoot.ps1` | **Remediation** — enables Secure Boot via Lenovo WMI BIOS interface |

### ⚠️ Before deploying — BIOS password configuration

The remediation script requires your organisation's BIOS supervisor password to write BIOS settings. Open `Remediate-LenovoSecureBoot.ps1` and update the placeholder values on these lines:

```powershell
$OldPass1 = "," + "Password_1" + $Encoding   # Replace Password_1 with your old BIOS password
$OldPass2 = "Password_1" + $Encoding          # Replace Password_1 with your old BIOS password
$NewPass1 = "," + "Password_2" + $Encoding   # Replace Password_2 with your current BIOS password
$NewPass2 = "Password_2" + $Encoding          # Replace Password_2 with your current BIOS password
```

If your organisation uses only one BIOS password (not rotated), set both `Password_1` and `Password_2` to the same value.

### How it works

**Detection logic:**
1. Queries `Lenovo_BiosSetting` WMI class in `root\WMI` namespace
2. Looks for the `SecureBoot` setting
3. Returns compliant (`SecureBoot,Enable`) or non-compliant (`SecureBoot,Disable`)

**Remediation logic:**
1. Suspends BitLocker for one reboot cycle before touching BIOS settings
2. Verifies the Lenovo WMI namespace is accessible
3. Tests the old BIOS password, falls back to new password
4. Calls `Lenovo_SetBiosSetting` to set `SecureBoot,Enable`
5. Saves via `Lenovo_SaveBiosSettings`
6. Logs transcript to `C:\Windows\Logs\Temp\scripts\SecureBootRemediation.log`

**Important:** BitLocker is suspended for exactly one reboot — this is intentional and required so the BIOS change does not trigger a BitLocker recovery prompt. After the reboot BitLocker re-enables automatically.

### Intune deployment

1. Intune admin centre → **Devices** → **Scripts and remediations** → **Create**
2. Name: `Lenovo Secure Boot Enable`
3. Detection script: `Detect-LenovoSecureBoot.ps1`
4. Remediation script: `Remediate-LenovoSecureBoot.ps1`
5. Run as: **System** (64-bit)
6. Assign to: Lenovo device group (filter by manufacturer = Lenovo)

---

## References

- [Windows Secure Boot certificate expiration and CA updates — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [Secure Boot Status Report in Windows Autopatch — Microsoft Learn](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/monitor/alerts-remediations)
- [KB5095093 — June 23, 2026 Preview — Microsoft Support](https://support.microsoft.com/en-us/topic/june-23-2026-kb5095093-os-builds-26200-8737-and-26100-8737-preview-0e2a20f2-cf9e-46f8-9f08-e6996220882d)
- [How to Update Secure Boot Certificate Using Intune — System Center Dudes](https://www.systemcenterdudes.com/how-to-update-for-intune-secure-boot-certificate/)
- [Intune Proactive Remediations documentation — Microsoft Learn](https://learn.microsoft.com/en-us/mem/intune/fundamentals/remediations)

---

## Author

**Imran Awan** — [linkedin.com/in/imran76awan](https://www.linkedin.com/in/imran76awan/) | [endpointweekly.com](https://endpointweekly.com)
