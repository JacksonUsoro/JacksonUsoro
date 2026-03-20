<#
.SYNOPSIS
    Ensures 'Allow user control over installs' is set to 'Disabled' by configuring 
    the EnableUserControl registry value.

.DESCRIPTION
    This script audits the HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer path 
    for the 'EnableUserControl' DWORD. If it is missing or not set to 0, the script 
    creates the key/value to comply with security hardening standards (STIG/CIS).

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : March 20, 2026
    Last Modified   : March 20, 2026
    Version         : 1.0
    Severity        : Medium
    Vuln ID         : V-254420
    STIG-ID         : WN11-CC-000310

.TESTED ON
    Date(s) Tested  : March 20, 2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Enterprise
    PowerShell Ver. : 5.1.22621.1

.USAGE
    Open PowerShell as Administrator and run:
    PS C:\> .\Set-InstallerUserControl.ps1
#>

# Define the registry details
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$name = "EnableUserControl"
$value = 0

Write-Host "Checking compliance for: Allow user control over installs..." -ForegroundColor Cyan

# 1. Check if the Registry Path exists; if not, create it
if (-not (Test-Path $registryPath)) {
    Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
    New-Item -Path $registryPath -Force | Out-Null
}

# 2. Get the current value of the property
$currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

# 3. Logic to Check and Fix
if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
    Write-Host "Finding: Policy is not configured correctly or is missing." -ForegroundColor Red
    
    try {
        Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord -Force
        Write-Host "Fix applied: $name has been set to $value (Disabled)." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to apply fix. Ensure you are running as Administrator. Error: $_"
    }
}
else {
    Write-Host "Compliant: The policy is already set to Disabled (0)." -ForegroundColor Green
}
