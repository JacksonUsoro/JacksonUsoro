<#
.SYNOPSIS
    Remediates finding: Require a password when a computer wakes (on battery)

.DESCRIPTION
    This script checks if the system requires a password when waking from sleep on battery power. 
    If the registry value does not exist or is not configured to the required value (1), 
    this script will flag it as a finding and automatically enforce the correct setting.
    
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
    Value Name: DCSettingIndex
    Value Type: REG_DWORD
    Value: 1

.NOTES
    Author: Jackson Usoro
    Date: 03/12/2026
    Component: Windows 10 STIG Remediation
#>

[CmdletBinding()]
param ()

begin {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $name = "DCSettingIndex"
    $type = "DWord"
    $expectedValue = 1

    Write-Verbose "Starting check for Power Policy: Require a password when a computer wakes (on battery)"
}

process {
    # -------------------------------------------------------------------
    # STEP 1: CHECK (Detecting the Finding)
    # -------------------------------------------------------------------
    $keyExists = Test-Path $registryPath
    $currentValue = $null

    if ($keyExists) {
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name
    }

    if ($keyExists -and $currentValue -eq $expectedValue) {
        Write-Output "[STATUS] Compliant: The value is already configured correctly ($name = $currentValue)."
    }
    else {
        Write-Warning "[STATUS] Finding detected!"
        if (-not $keyExists) {
            Write-Warning "The registry path does not exist."
        } else {
            Write-Warning "The registry value is currently set to: $currentValue (Expected: $expectedValue)"
        }
        
        # -------------------------------------------------------------------
        # STEP 2: FIX (Applying the Policy)
        # -------------------------------------------------------------------
        Write-Output "Applying remediation..."
        
        try {
            # Create the registry path if it doesn't exist
            if (-not $keyExists) {
                New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
                Write-Verbose "Created missing registry path: $registryPath"
            }
            
            # Set the registry value (Using New-ItemProperty with -Force handles both creation and updating)
            New-ItemProperty -Path $registryPath -Name $name -Value $expectedValue -PropertyType $type -Force -ErrorAction Stop | Out-Null
            
            # -------------------------------------------------------------------
            # STEP 3: VERIFY (Confirming the Fix)
            # -------------------------------------------------------------------
            $newValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name
            if ($newValue -eq $expectedValue) {
                Write-Output "[STATUS] Remediated: $name successfully set to $newValue."
            } else {
                Write-Error "Verification failed. The value could not be confirmed."
            }
        }
        catch {
            Write-Error "An error occurred while applying the fix: $($_.Exception.Message)"
            Write-Warning "Ensure you are running this script from an elevated PowerShell prompt (Run as Administrator)."
        }
    }
}

end {
    Write-Verbose "Check and Remediation process complete."
}
