# Windows Hello for Business — device triage

Read-only tooling for working out why Windows Hello is not working on **one** device.

`dsregcmd /status` shows you one surface. Hello health lives on eight. `NgcSet : YES` only means a
key was created at some point — not that it still exists, that the service which signs with it is
running, that the token it feeds is valid, or that the person has used it once this month.

Full write-up: <https://endpointweekly.com/blog/whfb-device-triage-report-offline-viewer.html>

## What is here

| File | What it does | Writes anything? |
|---|---|---|
| `Get-WHFBDeviceReport.ps1` | Reads all eight surfaces, scores a verdict, writes a JSON report | Only the JSON report |
| `whfb-report-viewer.html` | Offline viewer for that JSON. One file, no libraries, no network calls | No |
| `Detect-WHFBDeviceHealth.ps1` | Intune Proactive Remediation detection, same checks in the same order | No |
| `Remediate-WHFBDeviceHealth.ps1` | Safe repairs only, and refuses the destructive ones on purpose | Starts services, triggers tasks, writes a log |

## Quick start

```powershell
# On the device you are troubleshooting, in an elevated PowerShell
.\Get-WHFBDeviceReport.ps1
```

It prints a summary and writes `WHFB-Device-<name>-<date>.json` beside itself. Download
`whfb-report-viewer.html`, open it from your own disk, and load that file.

> The viewer is deliberately **not** called `*-report.html`: this repository's `.gitignore` blocks
> that pattern so generated reports containing real tenant data can never be committed by accident.

```powershell
# Masks user names, device ID, Hello key ID and certificate thumbprints
.\Get-WHFBDeviceReport.ps1 -Anonymise

# Shorter history window, explicit output path
.\Get-WHFBDeviceReport.ps1 -Days 7 -JsonPath C:\Temp\device.json
```

## What the eight surfaces are

1. **Identity** — `dsregcmd`: join type, `DeviceAuthStatus`, device ID
2. **Certificate** — the `MS-Organization-Access` certificate and its expiry
3. **Security chip** — `Get-Tpm`: present, ready, enabled, owned
4. **Hello key** — `NgcSet`, the NGC container count, `KeySignTest`, `KeyProvider`
5. **Token** — `AzureAdPrt` and its update and expiry times
6. **Policy** — the `PassportForWork` values, including the convenience-PIN trap
7. **Services** — `NgcSvc`, `KeyIso`, `NgcCtnrSvc`, `WbioSrvc`, `TokenBroker`
8. **Behaviour** — Security 4624/4801 anchored against Hello and biometric events

## Two things that cause false alarms

**Trigger-started services.** `WbioSrvc` and `NgcCtnrSvc` start, do their work and stop again
within seconds. `Status: Stopped` is their normal resting state. Only `NgcSvc` and `KeyIso` showing
Stopped is a real fault, and these scripts flag only those two.

**Context.** `NgcSet` and `AzureAdPrt` are per-user values. Run the collector as the signed-in user
to see that user's state. A Proactive Remediation runs as SYSTEM and therefore reports the SYSTEM
context, which is not the person who raised the ticket. Use the detection script for fleet
visibility and the full report for the actual diagnosis.

## What the remediation deliberately will not do

- **Re-enrol Hello** when `NgcSet` is NO or the container is missing. The repair deletes the user's
  PIN and biometrics and needs them present.
- **Clear a TPM** that is not ready. That destroys every key on the device, BitLocker protectors
  included.
- **Re-join** a device that is not registered. That is an enrolment decision, not a repair.
- **Write `Enabled = 1`** when policy set it to 0. The next sync reverts it and hides the real
  policy problem.

In each case it logs the reason and exits non-zero, so the device stays visible rather than quietly
dropping off the list.

## Privacy

The JSON report contains user principal names and a sign-in history for that device. Treat it as a
support capture. Use `-Anonymise` before it leaves your team.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7
- Administrator for the Security log, the TPM state and the audit policy. Without it the script
  still runs and lists what it could not read instead of guessing.

## Licence

Free to use and adapt. Test in your own environment before deploying to a fleet.
