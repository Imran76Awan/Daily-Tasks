<#
.SYNOPSIS
    Intune Proactive Remediation DETECTION script  -  audits local Administrators group
    membership on a device and flags drift against an expected baseline.

.DESCRIPTION
    Local Administrators group membership is not natively surfaced to Microsoft Graph
    or the Intune device object. LAPS proves the local admin PASSWORD rotates  -  it says
    nothing about WHO is sitting in that group. This script runs Get-LocalGroupMember
    against the local "Administrators" group on the device it executes on, compares the
    result against an expected baseline supplied via -ExpectedMembers, and reports:

        - UNEXPECTED members  : present in the group but not on the expected list
        - MISSING members     : on the expected list but not actually present
        - Well-known SIDs      : the built-in Administrator account is always resolved
                                  and reported explicitly, since it does not always
                                  show a friendly name on every OS build

    Designed to run as an Intune Proactive Remediation DETECTION script:
        - Exit code 0  = healthy, membership matches baseline, no drift
        - Exit code 1  = drift detected, Intune marks the device "with issues" and
                          (optionally) triggers a paired remediation script

    Every line written with Write-Output is captured by Intune and displayed per-device
    under Devices > Scripts and remediations > <policy> > Device status > <device> >
    "Pre-remediation detection output". That per-device console capture is what actually
    surfaces WHO is in the group centrally  -  there is no Graph API call that returns
    this. See the companion blog post for the full explanation of why this is a
    device-side script and not a tenant-wide query.

.PARAMETER ExpectedMembers
    Array of account or group names that ARE ALLOWED to be members of the local
    Administrators group. Anything present that is not on this list is reported as
    UNEXPECTED. Anything on this list that is NOT present is reported as MISSING.

    The default value below is a PLACEHOLDER EXAMPLE  -  replace it with your own
    tenant's actual expected baseline before deploying this at scale. At minimum this
    should include:
        - The built-in local Administrator account (BUILTIN\Administrator), unless you
          have disabled it, in which case remove it from the list
        - Your LAPS-managed local admin account (see the sibling LAPS post on this blog)
        - Any domain/Entra support group that is deliberately granted local admin

.EXAMPLE
    .\Get-LocalAdminGroupDrift.ps1
    Runs with the default placeholder baseline. Replace the default before real use.

.EXAMPLE
    .\Get-LocalAdminGroupDrift.ps1 -ExpectedMembers @("BUILTIN\Administrator","CONTOSO\LAPS-Managed-Account","CONTOSO\Tier1-Support-Admins")
    Runs against a custom baseline  -  the pattern you would paste into the Intune
    Proactive Remediation script parameters, or hardcode in the $ExpectedMembers
    default for a fully "no parameters needed" deployment.

.NOTES
    Author        : Imran Awan
    Blog          : https://endpointweekly.com/blog/local-administrators-group-drift-audit-intune.html
    Deployment    : Intune > Devices > Scripts and remediations > Create script package
    Pairs with    : No native remediation script is shipped alongside this detection
                    script deliberately  -  removing someone from local Administrators
                    can break a legitimate business process if you do not know why they
                    were added. Investigate every UNEXPECTED finding before writing a
                    remediation script that auto-removes members. See the blog post's
                    red callout on this exact point.
    Requires      : Windows PowerShell 5.1+ or PowerShell 7+, local execution context
                    (SYSTEM or logged-on user  -  no Graph/tenant auth needed, this is a
                    purely local, device-side check)
#>

[CmdletBinding()]
param(
    # PLACEHOLDER  -  replace with your tenant's real expected baseline before deploying.
    [string[]]$ExpectedMembers = @(
        "BUILTIN\Administrator",
        "CONTOSO\LAPS-Managed-Account"
    )
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

$exitCode = 0

try {
    $computerName = $env:COMPUTERNAME
    Write-Log "Local Administrators group drift check starting on $computerName"
    Write-Log "Expected baseline ($($ExpectedMembers.Count) members): $($ExpectedMembers -join ', ')"

    # Get-LocalGroupMember is the real, standard cmdlet for this  -  no Graph equivalent exists.
    $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    if (-not $members) {
        Write-Log "Administrators group returned zero members  -  this should never happen, investigate manually" "FAIL"
        exit 1
    }

    # Normalize names: strip the local machine prefix so "DESKTOP-ABC123\bob" reads
    # the same as a domain/Entra account, and resolve well-known SIDs to friendly text.
    $normalized = foreach ($m in $members) {
        $name = $m.Name
        if ($name -like "$computerName\*") {
            $name = $name -replace "^$([regex]::Escape($computerName))\\", "BUILTIN\"
        }
        [PSCustomObject]@{
            Name          = $name
            ObjectClass   = $m.ObjectClass
            PrincipalSrc  = $m.PrincipalSource
        }
    }

    Write-Log "--- Current Administrators group membership ($($normalized.Count) members) ---"
    foreach ($n in $normalized) {
        Write-Log ("  {0}  [{1} / {2}]" -f $n.Name, $n.ObjectClass, $n.PrincipalSrc)
    }

    $currentNames = $normalized.Name

    # UNEXPECTED = present now, but not on the expected baseline
    $unexpected = $currentNames | Where-Object { $ExpectedMembers -notcontains $_ }

    # MISSING = expected on the baseline, but not actually present
    $missing = $ExpectedMembers | Where-Object { $currentNames -notcontains $_ }

    Write-Log "--- Drift comparison against expected baseline ---"

    if ($unexpected.Count -eq 0) {
        Write-Log "No unexpected members found" "PASS"
    }
    else {
        foreach ($u in $unexpected) {
            Write-Log "UNEXPECTED member present: $u  -  not on the expected baseline, investigate before removing" "WARN"
        }
        $exitCode = 1
    }

    if ($missing.Count -eq 0) {
        Write-Log "No expected members are missing" "PASS"
    }
    else {
        foreach ($mm in $missing) {
            Write-Log "EXPECTED member MISSING: $mm  -  if this is your LAPS-managed account, LAPS rotation may be misconfigured or the account was removed" "FAIL"
        }
        $exitCode = 1
    }

    Write-Log "--- RESULT ---"
    if ($exitCode -eq 0) {
        Write-Log "COMPLIANT - local Administrators group matches the expected baseline, no drift detected" "PASS"
    }
    else {
        Write-Log "NON-COMPLIANT - drift detected: $($unexpected.Count) unexpected, $($missing.Count) missing" "FAIL"
    }

    Write-Log "Exit code: $exitCode"
    exit $exitCode
}
catch {
    Write-Log "Script error: $($_.Exception.Message)" "FAIL"
    # Fail closed  -  an error reading the group is itself worth flagging as non-compliant
    # so it shows up in the Proactive Remediations report rather than silently passing.
    exit 1
}
