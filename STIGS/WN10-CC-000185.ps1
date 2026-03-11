<#
.SYNOPSIS
    This script audits the "Set the default behavior for AutoRun" policy to ensure it is set to "Do not execute any autorun commands" (NoAutorun = 1), and automatically updates the registry value if it is found to be non-compliant.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-11
    Last Modified   : 2026-03-11
    Version         : 1.0
    Severity        : CAT 1
    VUln ID         : V-220828
    STIG-ID         : WN10-CC-000185

.TESTED ON
    Date(s) Tested  : 3/11/2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 10 Enterprise
    PowerShell Ver. : 5.1.19041.6456

.USAGE  
  PS C:\> .\Fix-AutoRunPolicy.ps1 
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as an Administrator. Please launch PowerShell as Admin and try again."
    exit
}

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName    = "NoAutorun"
$desiredValue = 1
$valueType    = "DWord"
$needsFix     = $false

# --- AUDIT PHASE ---

Write-Host "Analyzing AutoRun Behavior Policy..." -ForegroundColor Cyan

# Check if the registry key path exists
if (Test-Path -Path $registryPath) {
    # Check if the specific value exists and matches the desired value
    $currentProperty = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
    
    if ($null -eq $currentProperty -or $currentProperty.$valueName -ne $desiredValue) {
        Write-Host "FINDING: '$valueName' is either missing or not set to $desiredValue." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: '$valueName' is correctly configured to $desiredValue." -ForegroundColor Green
        $needsFix = $false
    }
}
else {
    Write-Host "FINDING: The registry path '$registryPath' does not exist." -ForegroundColor Red
    $needsFix = $true
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    try {
        # Create the registry key path if it does not exist
        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Set the registry value to enforce "Do not execute any autorun commands"
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type $valueType -Force | Out-Null
        
        Write-Host " - REMEDIATION APPLIED: AutoRun policy '$valueName' has been set to $desiredValue." -ForegroundColor Green
    }
    catch {
        Write-Host " - REMEDIATION FAILED: Failed to apply the fix. Please verify registry permissions." -ForegroundColor Red
    }
}
