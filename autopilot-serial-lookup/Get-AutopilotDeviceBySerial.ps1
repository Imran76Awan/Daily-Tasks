<#
.SYNOPSIS
    Look up one or more Windows Autopilot devices by serial number using Microsoft Graph.

.DESCRIPTION
    Queries the Microsoft Graph API via the Microsoft.Graph.DeviceManagement.Enrollment
    module to find Autopilot device registrations by exact serial number match.
    Supports single serial number lookup or bulk lookup from a CSV file.
    Exports results to a CSV with registration status, Group Tag, enrollment state, and model.

.PARAMETER SerialNumber
    A single serial number to look up.

.PARAMETER CsvPath
    Path to a CSV file containing serial numbers. The CSV must have a column named 'SerialNumber'.

.PARAMETER ExportCsv
    If specified, exports results to a CSV file in the same folder as the script.

.NOTES
    Requires the Microsoft.Graph.DeviceManagement.Enrollment module.
    Permission required: DeviceManagementServiceConfig.Read.All (delegated or application).

    Blog post: https://endpointweekly.com/blog/autopilot-device-serial-number-lookup-graph-powershell.html
    Author:    Imran Awan
    Version:   1.0

.EXAMPLE
    .\Get-AutopilotDeviceBySerial.ps1 -SerialNumber "ABC123XYZ456"
    Looks up a single device by serial number.

.EXAMPLE
    .\Get-AutopilotDeviceBySerial.ps1 -CsvPath "C:\Temp\serials.csv" -ExportCsv
    Bulk lookup from a CSV and exports results to CSV.
#>

[CmdletBinding()]
param (
    [Parameter(ParameterSetName = 'Single', Mandatory = $true)]
    [string]$SerialNumber,

    [Parameter(ParameterSetName = 'Bulk', Mandatory = $true)]
    [string]$CsvPath,

    [switch]$ExportCsv
)

#region Prerequisites
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.DeviceManagement.Enrollment')) {
    Write-Host "Installing Microsoft.Graph.DeviceManagement.Enrollment module..." -ForegroundColor Yellow
    Install-Module -Name 'Microsoft.Graph.DeviceManagement.Enrollment' -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph.DeviceManagement.Enrollment -ErrorAction Stop

# Connect if not already connected
try {
    $null = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Top 1 -ErrorAction Stop
} catch {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All" -ErrorAction Stop
}
#endregion

function Get-DeviceBySerial {
    param ([string]$SN)
    $device = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Filter "serialNumber eq '$SN'" -ErrorAction SilentlyContinue
    return [PSCustomObject]@{
        SerialNumber         = $SN
        Registered           = ($null -ne $device)
        GroupTag             = $device?.GroupTag
        EnrollmentState      = $device?.EnrollmentState
        Manufacturer         = $device?.Manufacturer
        Model                = $device?.Model
        ManagedDeviceId      = $device?.ManagedDeviceId
        AzureAdDeviceId      = $device?.AzureActiveDirectoryDeviceId
        LastContactedDateTime = $device?.LastContactedDateTime
        DisplayName          = $device?.DisplayName
        AutopilotId          = $device?.Id
    }
}

#region Run lookup
$results = @()

if ($PSCmdlet.ParameterSetName -eq 'Single') {
    Write-Host "Looking up serial number: $SerialNumber" -ForegroundColor Cyan
    $result = Get-DeviceBySerial -SN $SerialNumber.Trim()
    $results += $result
    if ($result.Registered) {
        Write-Host "FOUND" -ForegroundColor Green
        $result | Format-List
    } else {
        Write-Host "NOT REGISTERED in Autopilot" -ForegroundColor Red
    }
} else {
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }
    $serials = Import-Csv -Path $CsvPath
    if (-not ($serials | Get-Member -Name 'SerialNumber' -ErrorAction SilentlyContinue)) {
        Write-Error "CSV must have a 'SerialNumber' column."
        exit 1
    }
    $total = $serials.Count
    $i = 0
    foreach ($row in $serials) {
        $i++
        $sn = $row.SerialNumber.Trim()
        Write-Progress -Activity "Autopilot Lookup" -Status "$i of $total — $sn" -PercentComplete (($i / $total) * 100)
        $result = Get-DeviceBySerial -SN $sn
        $results += $result
        $status = if ($result.Registered) { 'FOUND' } else { 'NOT REGISTERED' }
        Write-Host "$sn — $status" -ForegroundColor $(if ($result.Registered) { 'Green' } else { 'Yellow' })
    }
    Write-Progress -Activity "Autopilot Lookup" -Completed

    $found = ($results | Where-Object { $_.Registered }).Count
    Write-Host "`nSummary: $found registered / $total total" -ForegroundColor Cyan
}
#endregion

#region Export
if ($ExportCsv) {
    $outPath = Join-Path $PSScriptRoot "AutopilotLookup-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    $results | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "Exported to: $outPath" -ForegroundColor Green
}
#endregion

return $results
