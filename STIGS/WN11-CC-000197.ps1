<#
.SYNOPSIS
    This script audits the "DisableWindowsConsumerFeatures" registry value to ensure it is set to 1, and automatically disables Microsoft consumer experiences (such as promoted apps and suggestions) if the policy is found to be disabled or missing.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-11
    Last Modified   : 2026-02-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197
    
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-CC-000197.ps1 
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
$requiredValue = 1

# --- AUDIT PHASE ---

$needsFix = $false

# Check if the registry key exists
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
    elseif ($regItem.$valueName -ne $requiredValue) {
        Write-Host "FINDING: '$valueName' is set to $($regItem.$valueName). It must be set to $requiredValue." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: '$valueName' is set to $requiredValue." -ForegroundColor Green
    }
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    # 1. Create the registry path if it is missing.
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host " - Created missing registry path structure." -ForegroundColor Cyan
    }

    # 2. Set DisableWindowsConsumerFeatures to 1.
    # This disables "Consumer Experiences" (like promoted apps in the Start Menu, 
    # "fun facts" on the lock screen, etc.).
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord
    
    Write-Host " - REMEDIATION APPLIED: '$valueName' has been set to $requiredValue." -ForegroundColor Green
}
