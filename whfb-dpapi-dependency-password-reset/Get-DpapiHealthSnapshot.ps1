<#
.SYNOPSIS
    Read-only DPAPI snapshot to help tell a DPAPI (password-reset) problem apart
    from a Windows Hello for Business fault.

.DESCRIPTION
    Changes nothing. Reports:
      1. The user's DPAPI master keys (path + LastWriteTime) under
         %APPDATA%\Microsoft\Protect\<SID> - a master key whose timestamp jumps to
         just after a reset is the new one; secrets tied to the old key are orphaned.
      2. A count of Credential Manager entries (via cmdkey) so you can see the
         surface that a DPAPI failure would affect.
      3. WHfB health (NgcSet) to confirm Hello itself is fine - if it is, a
         credential/Wi-Fi failure is DPAPI, not Hello.

    It does NOT decrypt anything and cannot recover an orphaned master key.

.EXAMPLE
    .\Get-DpapiHealthSnapshot.ps1

.NOTES
    Author : Imran Awan (EndpointWeekly)
    Blog   : https://endpointweekly.com/blog/whfb-dpapi-dependency-password-reset.html
    Safe   : READ-ONLY.
    Run as : The affected signed-in user.
#>

[CmdletBinding()]
param()

# 1. DPAPI master keys
$protectRoot = Join-Path $env:APPDATA 'Microsoft\Protect'
$masterKeys = @()
if (Test-Path $protectRoot) {
    $masterKeys = Get-ChildItem $protectRoot -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9a-fA-F]{8}-' } |
        Select-Object Name, LastWriteTime
}

# 2. Credential Manager entry count
$credCount = 0
try { $credCount = @((& cmdkey /list 2>$null) | Select-String -Pattern 'Target:').Count } catch { }

# 3. WHfB health
$ds = @{}
foreach ($line in (& dsregcmd /status 2>$null)) {
    if ($line -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.+?)\s*$') { $ds[$Matches[1]] = $Matches[2].Trim() }
}

Write-Host ''
Write-Host '  DPAPI Health Snapshot' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------'
Write-Host ('  DPAPI master keys found : {0}' -f $masterKeys.Count)
foreach ($k in ($masterKeys | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
    Write-Host ('    {0}  {1}' -f $k.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $k.Name)
}
Write-Host ('  Credential Manager entries : {0}' -f $credCount)
Write-Host ('  WHfB NgcSet (Hello OK)     : {0}' -f $ds['NgcSet'])
Write-Host '  ------------------------------------------------------------'
if ($ds['NgcSet'] -eq 'YES') {
    Write-Host '  Hello is healthy. If saved credentials / Wi-Fi are failing, suspect DPAPI' -ForegroundColor Yellow
    Write-Host '  (a recent password RESET) - not Windows Hello. Do not delete the Hello container.' -ForegroundColor Yellow
} else {
    Write-Host '  Snapshot captured.' -ForegroundColor Green
}
Write-Host ''
