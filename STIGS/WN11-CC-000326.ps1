<#
.SYNOPSIS
    This script audits the "EnableScriptBlockLogging" registry value to ensure it is set to 1, and automatically enables the policy if it is found to be disabled or missing.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-10
    Last Modified   : 2026-02-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000326

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-CC-000326.ps1 
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$valueName = "EnableScriptBlockLogging"
$requiredValue = 1

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
    # The -Force parameter creates the full directory structure (Windows\PowerShell\ScriptBlockLogging) 
    # if any parent keys are missing.
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host " - Created missing registry path structure." -ForegroundColor Cyan
    }

    # 2. Enable Script Block Logging.
    # We set 'EnableScriptBlockLogging' to 1 (Enabled).
    # This forces PowerShell to log the full text of blocks of code as they are executed 
    # to the Event Viewer (Microsoft-Windows-PowerShell/Operational).
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValue -Type DWord
    
    Write-Host " - REMEDIATION APPLIED: '$valueName' has been set to $requiredValue." -ForegroundColor Green
}
