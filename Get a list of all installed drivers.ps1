# Create an empty array to store the list of installed apps
$installedApps = @()

# Get a list of all installed apps
$allApps = Get-WmiObject -Class Win32_Product | Sort-Object -Property Name

# Iterate through the list of apps
foreach($app in $allApps)
{
    # Create a new object to store the app info
    $appInfo = New-Object PSObject

    # Add the app name and description to the object
    $appInfo | Add-Member -MemberType NoteProperty -Name "Name" -Value $app.Name
    $appInfo | Add-Member -MemberType NoteProperty -Name "Description" -Value $app.Description

    # Add the app info object to the array
    $installedApps += $appInfo
}

# Export the array to a CSV file
$installedApps | Export-Csv -Path "C:\installed_apps.csv" -NoTypeInformation
