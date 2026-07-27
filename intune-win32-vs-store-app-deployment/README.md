# Intune Win32 vs Store App Deployment

Companion scripts for the EndpointWeekly post:
**[Microsoft Intune: Win32 vs. Store App Deployment — Complete Guide](https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html)**

## Scripts

| Script | What it does |
|--------|--------------|
| `01-PackageWin32App.ps1` | Wraps `IntuneWinAppUtil.exe` to convert a Win32 app source folder into the `.intunewin` format required for Intune upload. |
| `02-Win32DetectionScript.ps1` | Template custom detection script for a Win32 app — checks a target executable's path **and** file version, deployed via Intune's "Use a custom detection script" option. |
| `03-CheckWin32AppStatus.ps1` | **Read-only.** Reports every Win32 app's per-device install state via Microsoft Graph, aggregate counts by default (safe to screenshot), full per-device detail with `-Detailed` (names masked unless `-IncludeNames`). |
| `04-TriggerIMESync.ps1` | Forces the Intune Management Extension to re-evaluate app assignments immediately instead of waiting for its ~8-hour poll cycle. Restarts the local IME service — not purely read-only. |
| `05-Win32AppFleetHealthSummary.ps1` | **Read-only.** Ranks every Win32 app by failure rate, flags apps above a configurable threshold (ignoring small-sample noise), and tracks day-over-day trend via saved CSV snapshots. |
| `06-Win32AppFailureAnalysisReport.ps1` | **Read-only.** Single-app lookup by default (prompts/disambiguates if a name matches multiple app objects). Builds a self-contained HTML report: donut chart of install states, ranked failure reasons with a decoded cause **and** a fix, per-device detail (names masked). |
| `07-Win32AppFleetTriage.ps1` | **Read-only.** Chains 05 and 06: ranks every app fleet-wide, then automatically pulls the full failure breakdown for every app (not just flagged ones) into one combined HTML report — click any app in the ranking table to jump to its own donut chart, failure reasons, and per-device table with a "days since last activity" column. |

## Requirements

- **Modules:** `Microsoft.Graph.Authentication`, `Microsoft.Graph.DeviceManagement`, `Microsoft.Graph.Reports`
  ```powershell
  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Reports -Scope CurrentUser
  ```
- **Permission:** `DeviceManagementApps.Read.All` (Application, for app-only cert auth) or delegated with `-Interactive`
- **01:** `IntuneWinAppUtil.exe` downloaded separately from [microsoft/Microsoft-Win32-Content-Prep-Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
- **04:** Local administrator rights (restarts a Windows service)

If you see `Could not load file or assembly 'Microsoft.Graph.Authentication.Core...'`, you have mismatched Graph SDK submodule versions installed side by side — scripts 03/05/06/07 pin a specific version (`$graphModuleVersion` near the top) to avoid this; adjust it to whatever matching set you have installed (`Get-Module -ListAvailable Microsoft.Graph.*`).

## Authentication

All Graph-connected scripts support two modes:

- **App-only (certificate)** — default. Fill in `$tenantId`, `$clientId`, `$thumbprint` at the top of each script.
- **Interactive** — add `-Interactive` to sign in as an admin instead.

## Privacy

Scripts 03/06/07 mask device names and usernames by default (first 2 characters + asterisks). Use `-IncludeNames` only when you need real values, and never share that output externally — these reports can return thousands of real employee names and device names in a single run.

## A real bug found while building this

Microsoft Graph's `getDeviceAppInstallationStatusReport` returns columns **alphabetically sorted**, not in the order passed to `-select`. Scripts 03/06/07 read the report's own `Schema` field to map column name → index at runtime rather than assuming positional order — don't remove that mapping if you modify these scripts.
