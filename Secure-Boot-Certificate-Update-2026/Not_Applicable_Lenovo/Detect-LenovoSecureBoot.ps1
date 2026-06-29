####################################
#  Intune Proactive Remediation
#  Detection: Secure Boot (Lenovo)
#  Exit 0 = Compliant (SecureBoot enabled)
#  Exit 1 = Not Compliant (remediation required)
####################################

try {
    $SecureBoot = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI -ErrorAction Stop |
                  Where-Object { $_.CurrentSetting -match "SecureBoot" } |
                  Select-Object -ExpandProperty CurrentSetting

    if ($SecureBoot -eq "SecureBoot,Enable") {
        Write-Host "Compliant: SecureBoot is enabled."
        exit 0
    }
    elseif ($SecureBoot -eq "SecureBoot,Disable") {
        Write-Host "Not Compliant: SecureBoot is disabled."
        exit 1
    }
    else {
        Write-Host "Not Compliant: SecureBoot setting not found or unrecognised value: $SecureBoot"
        exit 1
    }
}
catch {
    Write-Host "Error querying Lenovo BIOS WMI: $_"
    exit 1
}
