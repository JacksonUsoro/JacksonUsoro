<#
.SYNOPSIS
    This script audits the "Account lockout duration" policy to ensure it is set to 15 minutes or greater (or 0), and automatically updates the policy to 15 if it is found to be non-compliant.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-10
    Last Modified   : 2026-03-10
    Version         : 1.0
    Severity        : Medium
    Vuln ID         : V-220739
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 3/10/2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 10 Pro
    
.USAGE  
  PS C:\> .\AccountLockoutDuration.ps1 
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as an Administrator. Please launch PowerShell as Admin and try again."
    exit
}

$minimumRequired = 15
$needsFix = $false

# --- AUDIT PHASE ---

Write-Host "Analyzing Account Lockout Duration Policy..." -ForegroundColor Cyan

# Retrieve the current account policy settings
$netAccountsOutput = net accounts
$durationLine = $netAccountsOutput | Select-String -Pattern "Lockout duration \(minutes\):"

if ($durationLine -match "Lockout duration \(minutes\):\s+(\d+)") {
    $currentDuration = [int]$matches[1]
    
    if ($currentDuration -lt $minimumRequired -and $currentDuration -ne 0) {
        Write-Host "FINDING: Account lockout duration is set to $currentDuration minutes. It must be $minimumRequired or greater (or 0)." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: Account lockout duration is set to $currentDuration minutes." -ForegroundColor Green
        $needsFix = $false
    }
}
else {
    Write-Host "FINDING: Could not retrieve the current Account Lockout Duration. Please verify system state." -ForegroundColor Red
    $needsFix = $true
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    try {
        # Set the lockout duration to 15. 
        # Note: This command will fail if the Account Lockout Threshold is set to 0.
        net accounts /lockoutduration:$minimumRequired | Out-Null
        
        Write-Host " - REMEDIATION APPLIED: Account lockout duration has been set to $minimumRequired minutes." -ForegroundColor Green
    }
    catch {
        Write-Host " - REMEDIATION FAILED: Failed to apply the fix. Ensure your Account Lockout Threshold is set to a value greater than 0 before setting a duration." -ForegroundColor Red
    }
}
