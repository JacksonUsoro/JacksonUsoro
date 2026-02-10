<#
.SYNOPSIS
    This script audits the "DeviceEnumerationPolicy" registry value to ensure it is set to 0 (Blocking incompatible devices), and automatically creates or updates the registry key if it is found to be non-compliant.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-10
    Last Modified   : 2026-02-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-EP-000310.ps1 
#>

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
$valueName = "DeviceEnumerationPolicy"
$requiredValue = 0

# --- AUDIT PHASE ---

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
        $needsFix = $false
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

    # 2. Set DeviceEnumerationPolicy to 0.
    # A value of 0 typically configures the policy to "Block all" for external devices 
    # that are incompatible with Kernel DMA Protection, preventing DMA attacks.
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord
    
    Write-Host " - REMEDIATION APPLIED: '$valueName' has been set to $requiredValue." -ForegroundColor Green
}
