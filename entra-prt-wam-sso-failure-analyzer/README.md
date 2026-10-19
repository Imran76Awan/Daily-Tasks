# PRT, WAM and SSO failure analyser — Intune Remediations package

Find out why a correctly joined Windows device keeps prompting a user for Microsoft 365 sign-in,
for the user who is actually affected. Then repair it automatically where that is safe.

A Primary Refresh Token (PRT) is issued **per user, per device**. Intune runs scripts as SYSTEM, and
`dsregcmd /status` run as SYSTEM shows SYSTEM's SSO state, not the person who raised the ticket.
This package collects the PRT state inside each signed-in user's own session. It correlates that
with the AAD event logs that only SYSTEM can read, and classifies the result into one of ten causes.

## What is here

| File | What it does | Changes anything? |
|---|---|---|
| `Detect-PrtSsoHealth.ps1` | The analyser. It is also the Intune **detection** script. It collects per-user state, groups AAD Analytic 1006→1007 transactions, classifies the failure, writes a JSON report and prints a one-line verdict for Intune. | Enables the AAD Analytic channel if it is off (use `-NoLogChanges` to skip this). It writes the report and creates and removes a one-shot scheduled task. |
| `Remediate-PrtSsoHealth.ps1` | Intune **remediation** script. It runs only the repairs attached to each finding, for users who are still signed in. | Yes. Safe repairs only (see below). |
| `prt-sso-report-viewer.html` | Offline viewer for the JSON report. One file, no libraries, no network calls. | No |

## What it extracts

For **each interactive user**, collected in that user's context through a one-shot scheduled task:

- `AzureAdPrt`, `AzureAdPrtUpdateTime`, `AzureAdPrtExpiryTime` (plus `EnterprisePrt`, `OnPremTgt`, `CloudTgt`)
- `AcquirePrtDiagnostics` and `RefreshPrtDiagnostics`, parsed separately: Previous Prt Attempt, **Attempt Status**,
  User Identity, **Credential Type**, **Correlation ID**, Endpoint URI, **HTTP Error**, **HTTP Status**,
  **Server Error Code**, **Server Error Description**
- `WamDefaultSet`, `WamDefaultAuthority`, `WamDefaultId`, the Microsoft.AAD.BrokerPlugin package state, and Office work identities
- **Current Windows UPN** (the CloudAP identity cache, which is the name Windows requests the PRT with) and **`whoami /upn`**
- **User SID**, the SID type (Entra ID `S-1-12-1-…`, AD, or local), and the **domain SID**
  (from the LSA policy cache, so no domain controller is needed)
- `NgcSet` and the user's WinINet proxy

For the **device**, collected as SYSTEM: join state, `DeviceAuthStatus`, the MS-Organization-Access
certificate, the TokenBroker, NgcSvc and KeyIso services, the WinHTTP proxy, and a TLS probe of
`login.microsoftonline.com`, `device.login.microsoftonline.com` and `enterpriseregistration.windows.net`.
The probe records the certificate issuer and root, so TLS inspection shows up directly.

## Correlating with the AAD event logs

`Applications and Services Logs → Microsoft → Windows → AAD → Operational / Analytic`

- **Analytic** event **1006** opens a PRT acquisition flow and **1007** closes it. Every event between
  them is one authentication transaction. If a 1006 arrives while a flow is still open, the open flow
  is closed and marked *unterminated*.
- **Operational** events are attached to a transaction when they fall in its time window or carry
  the same **Correlation ID**.
- The Correlation ID from `AcquirePrtDiagnostics`/`RefreshPrtDiagnostics` links the dsregcmd result
  to its transaction. The same ID is what you search for in the Entra sign-in log.
- Transactions are assigned to a user by the event's user SID, the UPN in the event text or the
  Correlation ID. On a single-user device, transactions with no attribution belong to that user.

The Analytic channel is **off by default**. The first detection run enables it (32 MB), so
transactions appear from the next run onward. Use `-TransactionStartId`/`-TransactionEndId` if your
build logs the flow under different IDs.

## How failures are classified

The primary verdict uses root-cause order. A TLS-inspecting proxy also produces credential and token
errors, so a lower category is only the primary cause when nothing above it explains the failure.

| # | Category | Typical evidence | Automatic repair |
|---|---|---|---|
| 1 | Device join failure | `DeviceAuthStatus` not SUCCESS, missing or expired device cert, hybrid not completed, AADSTS135011/700003/50155, `0x801cxxxx` | Hybrid only: trigger `Automatic-Device-Join` |
| 2 | Proxy or TLS inspection interference | TLS probe issuer is not Microsoft or DigiCert, non-zero HTTP Error, `0xcaa82f8f`/`0xcaa82efd`/`0xcaa82ee2`, HTTP 407 | None (network team) |
| 3 | Federation failure | Endpoint URI is not a Microsoft login host, `0xcaa9xxxx` WS-Trust errors, AADSTS50008/50107 | None (IdP team) |
| 4 | Incorrect UPN | Non-routable suffix, `whoami /upn` ≠ CloudAP UPN ≠ PRT attempt identity, userrealm `Unknown`, AADSTS50034, `0xc000005f` | User toast: sign out and in |
| 5 | User SID missing from the token | `0xc004848a` (USER_SID_IS_EMPTY), no CloudAP cache entry for the SID | None (Entra Connect sync) |
| 6 | User credential failure | AADSTS50126/50053/50055/50057/50173, `0xc000006a`, `0xc0000234`, `0xc000006d` + `invalid_grant` | User toast: lock and unlock with the current password |
| 7 | Conditional Access denial | AADSTS53000/53001/53003/50097 (Fail), 50076/50079 (Warn) | Compliance codes: MDM sync, then PRT refresh |
| 8 | Windows Hello credential issue | Credential Type NGC with a failure, `0x80090016`, TPM `0x8028xxxx`, NgcSvc/KeyIso stopped | Start NgcSvc/KeyIso |
| 9 | WAM account inconsistency | `WamDefaultSet: NO` with a PRT, authority not `organizations`, BrokerPlugin missing, TokenBroker disabled, `0xcaa5001c` | Start TokenBroker, re-register AAD.BrokerPlugin, refresh PRT |
| 10 | Stale token state | `AzureAdPrt: NO`, PRT expired, not renewed for `-StaleHours` (12), AADSTS70008/700082 | `dsregcmd /refreshprt` as the user |

A dsregcmd diagnostic block, or an Operational error, that is **older than the last successful PRT
renewal** is downgraded to *Info*. It is history, not the current fault.

## Deploy with Intune

**Devices → Scripts and remediations → Remediations → Create**

| Setting | Value |
|---|---|
| Detection script file | `Detect-PrtSsoHealth.ps1` |
| Remediation script file | `Remediate-PrtSsoHealth.ps1` |
| Run this script using the logged-on credentials | **No** (it must run as SYSTEM; it reaches the user itself) |
| Enforce script signature check | No (or sign both files) |
| Run script in 64-bit PowerShell | **Yes** |
| Schedule | Every 1–4 hours for a pilot, daily for the fleet |

Remediations needs Windows Enterprise E3/E5 (or equivalent) licensing. Before you upload, review the
configuration block at the top of `Remediate-PrtSsoHealth.ps1`. Intune cannot pass parameters, so
that block is where behaviour is set.

**Reading the results:** the *Pre-remediation detection output* column holds one line per device, for example:

```
UNHEALTHY | primary=Proxy or TLS inspection interference | user=AzureAD\JaneDoe upn=jane@contoso.com PRT=NO age=?h cat=ProxyTls code=0xcaa82f8f corr=6364… | join=Microsoft Entra joined | tx=3 failed=2
```

The full report stays on the device at `C:\ProgramData\EndpointWeekly\PrtSso\PrtSso-latest.json`, with
the last 10 runs kept. Remediation actions are logged to `remediation.log` in the same folder. Open the
JSON in `prt-sso-report-viewer.html`.

**Exit codes:** detection exits 1 on any failure, or on a warning that has an automatic repair.
Remediation exits 0 only when every repair worked and nothing needs a person. Otherwise the device
stays visible in the report.

## What the remediation deliberately will not do

- **Leave and re-join the device.** `dsregcmd /leave` orphans BitLocker key escrow and the Intune
  enrolment tied to the device ID. You can opt in with `$AllowHybridRejoin` (hybrid devices only).
- **Clear the WAM/broker token cache.** It signs the user out of every Microsoft 365 app. You can
  opt in with `$AllowWamCacheReset`, which renames the cache folders instead of deleting them.
- **Change proxy, TLS inspection, AD FS, UPN, sync or Conditional Access settings.** Other teams own
  these. The remediation logs the finding with the fix and exits 1.
- **Delete a Windows Hello container or clear a TPM.** See `whfb-ngc-container-explained/` in this repo.

User notifications are limited to one per user per category every 24 hours. They are skipped while
the network path is broken, because asking someone to lock and unlock cannot help then. If a PRT
refresh succeeds, the token-path findings (credential, stale, WAM, CA, Hello) count as resolved.
Intune's post-remediation detection then confirms it.

## Run it by hand

```powershell
# Elevated prompt, as the affected user: full console report plus JSON
.\Detect-PrtSsoHealth.ps1 -HoursBack 72

# Strictly read-only, with no outbound calls
.\Detect-PrtSsoHealth.ps1 -NoLogChanges -SkipNetworkTests

# Masked report for a vendor or forum
.\Detect-PrtSsoHealth.ps1 -Anonymise -ReportPath C:\Temp\prt
```

## Privacy and security notes

- The report contains UPNs, SIDs, correlation IDs and event text. Treat it as a support capture. Use `-Anonymise` before it leaves your team.
- The user realm lookup sends the user's UPN to `login.microsoftonline.com/common/userrealm`, which is
  the same call Windows makes at sign-in. `-SkipNetworkTests` turns it off.
- The user-context task runs a fixed, embedded payload with the user's own rights. SYSTEM only parses
  its output as JSON. The report folder is locked to SYSTEM and Administrators (Users read-only), so a
  standard user cannot plant a report for the remediation to act on.

## Requirements

- Windows 10 1903+ or Windows 11. `dsregcmd /refreshprt` is used where the build supports it. Older
  builds fall back to asking the user to lock and unlock.
- Windows PowerShell 5.1 (the scripts are also syntax-compatible with PowerShell 7).
