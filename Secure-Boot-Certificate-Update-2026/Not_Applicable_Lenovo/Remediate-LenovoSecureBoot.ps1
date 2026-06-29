####################################
#  Intune Proactive Remediation
#  Remediation: Secure Boot (Lenovo)
#  Exit 0 = Remediation successful
#  Exit 1 = Remediation failed
####################################

## Create log directory if it doesn't exist
$LogDir = "C:\Windows\Logs\Temp\scripts"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Start-Transcript -Path "$LogDir\SecureBootRemediation.log" -Append -Force

try {

    ## --- Disable BitLocker scheduled tasks ---
    Write-Host "Disabling BitLocker scheduled tasks..."
    foreach ($task in @("BL-TakeAction2", "BL-Suspend2", "BL-Unsuspend2")) {
        try   { Disable-ScheduledTask -TaskName $task -ErrorAction Stop; Write-Host "  Disabled: $task" }
        catch { Write-Host "  Task not found or already disabled: $task" }
    }

    ## --- Suspend BitLocker and VERIFY it is actually suspended before continuing ---
    Write-Host "Suspending BitLocker..."
    try {
        $BLStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

        if ($BLStatus.ProtectionStatus -eq "On") {
            Suspend-BitLocker -MountPoint "C:" -RebootCount 1 -ErrorAction Stop

            ## Verify suspension took effect
            $BLCheck = Get-BitLockerVolume -MountPoint "C:"
            Write-Host "  BitLocker Protection Status after suspend: $($BLCheck.ProtectionStatus)"

            if ($BLCheck.ProtectionStatus -ne "Off") {
                Write-Host "  WARNING: BitLocker did not suspend as expected. Proceeding anyway."
            }
        } else {
            Write-Host "  BitLocker already suspended or not active. Status: $($BLStatus.ProtectionStatus)"
        }
    } catch {
        Write-Host "  BitLocker check/suspend error (non-fatal): $_"
    }

    ## --- Confirm WMI namespace is reachable ---
    Write-Host "Checking Lenovo WMI namespace..."
    try {
        Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI -ErrorAction Stop | Select-Object -First 1 | Out-Null
        Write-Host "  WMI namespace: accessible"
    } catch {
        Write-Host "  ERROR: Cannot access Lenovo WMI namespace."
        Stop-Transcript
        exit 1
    }

    ## --- Read current SecureBoot state ---
    $SBObject = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI |
                Where-Object { $_.CurrentSetting -match "SecureBoot" }

    if (-not $SBObject) {
        Write-Host "ERROR: SecureBoot setting not found in Lenovo WMI."
        Stop-Transcript
        exit 1
    }

    $SecureBootValue = $SBObject.CurrentSetting
    Write-Host "Current SecureBoot value: $SecureBootValue"

    if ($SecureBootValue -eq "SecureBoot,Enable") {
        Write-Host "SecureBoot is already enabled. No action needed."
        Stop-Transcript
        exit 0
    }

    ## --- BIOS Password Detection ---
    ## Older models (Old Models):                 PUT YOUR BIOS PASSWORD
    ## Newer models (New Models):                 PUT YOUR BIOS PASSWORD
    $Encoding = ",ascii,us"
    $OldPass1 = "," + "Password_1" + $Encoding
    $OldPass2 = "Password_1" + $Encoding
    $NewPass1 = "," + "Password_2" + $Encoding
    $NewPass2 = "Password_2" + $Encoding

    Write-Host "Testing BIOS password..."
    $OldTest = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings($OldPass2).return
    Write-Host "  Older password test: $OldTest"

    if ($OldTest -eq "Success") {
        $Pass1 = $OldPass1
        $Pass2 = $OldPass2
        Write-Host "  Using: older BIOS password"
    } else {
        $NewTest = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings($NewPass2).return
        Write-Host "  Newer password test: $NewTest"

        if ($NewTest -eq "Success") {
            $Pass1 = $NewPass1
            $Pass2 = $NewPass2
            Write-Host "  Using: newer BIOS password"
        } else {
            Write-Host "ERROR: Neither BIOS password accepted."
            Stop-Transcript
            exit 1
        }
    }

    ## --- Enable SecureBoot via WMI ---
    Write-Host "Setting SecureBoot to Enable..."
    $SetResult  = (Get-WmiObject -Class Lenovo_SetBiosSetting  -Namespace root\wmi).SetBiosSetting("SecureBoot,Enable$Pass1").return
    Write-Host "  SetBiosSetting result:   $SetResult"

    $SaveResult = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings($Pass2).return
    Write-Host "  SaveBiosSettings result: $SaveResult"

    if ($SaveResult -ne "Success") {
        Write-Host "FAILED: Could not save BIOS settings. Result: $SaveResult"
        Stop-Transcript
        exit 1
    }

    Write-Host "SUCCESS: SecureBoot enabled. Device will apply the change on next restart."
    Stop-Transcript
    exit 0

}
catch {
    Write-Host "Unhandled error: $_"
    Stop-Transcript
    exit 1
}
