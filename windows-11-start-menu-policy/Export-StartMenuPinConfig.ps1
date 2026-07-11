<#
.SYNOPSIS
    Builds and validates a ConfigureStartPins JSON payload for Intune OMA-URI deployment.

.DESCRIPTION
    ConfigureStartPins is the primary CSP for pinning apps to the Windows 11 Start menu.
    This script:
    - Resolves installed apps to their PackageFamilyName (needed for Store apps)
    - Outputs a valid ConfigureStartPins JSON payload
    - Optionally exports the payload ready for pasting into Intune Custom OMA-URI
    - Validates the JSON structure before export

    The output JSON can be pasted directly into:
    Intune > Devices > Configuration > Create policy > Windows 10/11 > Custom OMA-URI
    OMA-URI: ./Vendor/MSFT/Policy/Config/Start/ConfigureStartPins

.NOTES
    Blog post: https://endpointweekly.com/blog/windows-11-start-menu-policy-settings-intune-csp.html
    Run as: Standard user (registry reads) or Admin (for Get-AppxPackage on all users)
    Tested on: Windows 11 22H2, 23H2, 24H2

.EXAMPLE
    .\Export-StartMenuPinConfig.ps1
    # Lists installed apps and their PackageFamilyName; outputs a sample payload

.EXAMPLE
    .\Export-StartMenuPinConfig.ps1 -ExportJson
    # Exports ConfigureStartPins.json ready for Intune deployment

.EXAMPLE
    .\Export-StartMenuPinConfig.ps1 -AppNames "Microsoft.WindowsCalculator", "Microsoft.Notepad"
    # Generates a payload pinning only Calculator and Notepad
#>

[CmdletBinding()]
param(
    [string[]]$AppNames,
    [switch]$ExportJson,
    [string]$OutputPath = ".\ConfigureStartPins.json"
)

# ── Resolve app PackageFamilyNames ────────────────────────────────────────────
Write-Host "`n=== Available Apps (PackageFamilyName) ===" -ForegroundColor Cyan

try {
    $apps = Get-AppxPackage -ErrorAction Stop |
        Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -eq 'Store' } |
        Select-Object Name, PackageFamilyName |
        Sort-Object Name

    $apps | Format-Table Name, PackageFamilyName -AutoSize
    Write-Host "Total apps found: $($apps.Count)" -ForegroundColor Green
} catch {
    Write-Warning "Could not list apps: $_"
    $apps = @()
}

# ── Build pin list ────────────────────────────────────────────────────────────
# If specific app names were passed, resolve them; otherwise use a sensible default set
if ($AppNames -and $AppNames.Count -gt 0) {
    $pinned = @()
    foreach ($name in $AppNames) {
        $match = $apps | Where-Object { $_.Name -like "*$name*" } | Select-Object -First 1
        if ($match) {
            $pinned += @{ packagedAppId = $match.PackageFamilyName + "!App" }
            Write-Host "Resolved '$name' -> $($match.PackageFamilyName)" -ForegroundColor Green
        } else {
            Write-Warning "App '$name' not found on this device. Add its PackageFamilyName manually."
        }
    }
} else {
    # Default example set — edit to match your org's required apps
    Write-Host "`nNo -AppNames specified. Using example set (edit before deployment)." -ForegroundColor Yellow
    $pinned = @(
        # Microsoft built-ins (stable PackageFamilyNames)
        @{ packagedAppId = "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" },
        @{ packagedAppId = "Microsoft.Notepad_8wekyb3d8bbwe!App" },
        @{ packagedAppId = "Microsoft.WindowsStore_8wekyb3d8bbwe!App" },
        @{ packagedAppId = "MicrosoftCorporationII.MicrosoftEdge_8wekyb3d8bbwe!App" },
        # Company Portal (use this exact string for Company Portal)
        @{ packagedAppId = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App" }
    )

    # Example of a Win32 / desktop app pin (use desktopAppId, not packagedAppId)
    # $pinned += @{ desktopAppId = "MSEdge" }
}

if ($pinned.Count -eq 0) {
    Write-Warning "No apps resolved. Exiting."
    exit 1
}

# ── Build ConfigureStartPins payload ─────────────────────────────────────────
$payload = @{
    pinnedList = $pinned
}

$json = $payload | ConvertTo-Json -Depth 5 -Compress

Write-Host "`n=== ConfigureStartPins Payload ===" -ForegroundColor Cyan
Write-Host $json
Write-Host "`nOMA-URI: ./Vendor/MSFT/Policy/Config/Start/ConfigureStartPins" -ForegroundColor Yellow
Write-Host "Data type: String" -ForegroundColor Yellow

# ── Validate JSON ─────────────────────────────────────────────────────────────
try {
    $null = $json | ConvertFrom-Json -ErrorAction Stop
    Write-Host "`n[PASS] JSON is valid." -ForegroundColor Green
} catch {
    Write-Error "[FAIL] Invalid JSON: $_"
    exit 1
}

# ── Export ────────────────────────────────────────────────────────────────────
if ($ExportJson) {
    # Pretty-print for readability
    $prettyJson = $payload | ConvertTo-Json -Depth 5
    $prettyJson | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Exported to: $OutputPath" -ForegroundColor Green
    Write-Host "`nNext step: paste the compact JSON (not pretty) into Intune OMA-URI value field." -ForegroundColor Cyan
    Write-Host "Compact JSON for Intune:" -ForegroundColor Cyan
    Write-Host $json
}
