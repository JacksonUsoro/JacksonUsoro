<#
.SYNOPSIS
    This script audits the "Audit File System" advanced audit policy to ensure it is set to "Failure", and automatically updates the policy if it is found to be non-compliant.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-14
    Last Modified   : 2026-03-14
    Version         : 1.0
    Severity        : CAT 2
    Vuln ID         : V-256673
    STIG-ID         : WN11-AU-000581

.TESTED ON
    Date(s) Tested  : 3/14/2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Enterprise
    PowerShell Ver. : 5.1.22621.2506

.USAGE  
  PS C:\> .\Fix-AuditFileSystem.ps1 
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as an Administrator. Please launch PowerShell as Admin and try again."
    exit
}

$SubCategory = "File System"
$needsFix    = $false

# --- AUDIT PHASE ---

Write-Host "Analyzing Audit File System Policy..." -ForegroundColor Cyan

# Retrieve the current audit policy for File System
$currentPolicy = auditpol /get /subcategory:"$SubCategory" | Out-String

# Check if the policy string includes "Failure" (will catch both "Failure" and "Success and Failure")
if ($currentPolicy -match "Failure") {
    Write-Host "COMPLIANT: Advanced Audit Policy for '$SubCategory' is correctly configured to include 'Failure'." -ForegroundColor Green
    $needsFix = $false
}
else {
    Write-Host "FINDING: Advanced Audit Policy for '$SubCategory' is not set to 'Failure'." -ForegroundColor Red
    $needsFix = $true
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    try {
        # Set the audit policy to enforce Failure logging (leaves Success intact if currently configured)
        $applyPolicy = auditpol /set /subcategory:"$SubCategory" /failure:enable | Out-String
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " - REMEDIATION APPLIED: Audit policy '$SubCategory' has been successfully set to log Failures." -ForegroundColor Green
        } else {
            Write-Host " - REMEDIATION FAILED: auditpol returned an error. Details: $applyPolicy" -ForegroundColor Red
        }
    }
    catch {
        Write-Host " - REMEDIATION FAILED: Failed to apply the fix. Please verify system permissions and auditpol availability." -ForegroundColor Red
    }
}
