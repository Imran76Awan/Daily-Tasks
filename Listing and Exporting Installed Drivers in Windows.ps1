$drvs = Get-WmiObject -Class Win32_PnPSignedDriver
$drvs | Select-Object DeviceName, DriverVersion | Export-Csv -Path "$($env:USERPROFILE)\driver_list.csv" -NoTypeInformation
