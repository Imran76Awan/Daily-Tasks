<#
.SYNOPSIS
    Forces the Intune Management Extension (IME) to re-evaluate app assignments
    on the local device instead of waiting for its normal ~8-hour poll cycle.

.DESCRIPTION
    Gives three ways to trigger an immediate IME re-check: restart the IME
    service, kick the IME scheduled task directly, or just tail the IME log to
    see what it's currently doing. Useful when testing a new Win32 app
    assignment and you don't want to wait for the next scheduled poll.

.NOTES
    Author:      Imran Awan
    Blog:        https://endpointweekly.com/blog/intune-win32-vs-store-app-deployment.html
    Requires:    Local administrator rights
    Version:     1.0
    Date:        2026-07-24

.EXAMPLE
    .\04-TriggerIMESync.ps1
    Restarts the IME service, triggers its scheduled task, and tails the last
    50 lines of the IME log filtered for install/error activity.
#>

[CmdletBinding()]
param()

# Force IME to re-evaluate app assignments on local device (requires local admin)

# Method 1: Restart the IME service
Restart-Service -Name "IntuneManagementExtension" -Force

# Method 2: Trigger the IME scheduled task
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Intune*" } |
    Start-ScheduledTask

# Method 3: Check IME logs for recent activity
$logPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
Get-Content $logPath -Tail 50 | Select-String "Win32App|Install|Error|Failed"
