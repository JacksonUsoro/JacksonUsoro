<#
.SYNOPSIS
    This script audits the "MinimumPIN" registry value to ensure it is set to 6 or greater, and automatically creates or updates the registry key to 6 if it is found to be non-compliant.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-10
    Last Modified   : 2026-02-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000032

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-00-000032.ps1 
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$valueName = "MinimumPIN"
$minimumRequired = 6

# --- AUDIT PHASE ---

# Check if the registry key (folder) exists
if (-not (Test-Path $registryPath)) {
    Write-Host "FINDING: The registry path '$registryPath' is missing." -ForegroundColor Red
    $needsFix = $true
}
else {
    # Get the specific registry value
    $regItem = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

    if ($null -eq $regItem) {
        Write-Host "FINDING: The value '$valueName' is missing." -ForegroundColor Red
        $needsFix = $true
    }
    elseif ($regItem.$valueName -lt $minimumRequired) {
        Write-Host "FINDING: '$valueName' is set to $($regItem.$valueName). It must be $minimumRequired or greater." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: '$valueName' is set to $($regItem.$valueName)." -ForegroundColor Green
        $needsFix = $false
    }
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    # 1. Create the registry path if it was missing.
    # New-Item will create the full path structure (Policies\Microsoft\FVE) if intermediate keys are missing.
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host " - Created missing registry path: $registryPath" -ForegroundColor Cyan
    }

    # 2. Set the 'MinimumPIN' value to 6.
    # Set-ItemProperty creates the value if it doesn't exist, or overwrites it if it does.
    # We use Type DWord as specified in the requirements.
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $minimumRequired -Type DWord
    
    Write-Host " - REMEDIATION APPLIED: '$valueName' has been set to $minimumRequired." -ForegroundColor Green
}
