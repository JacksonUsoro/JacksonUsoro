<#
.SYNOPSIS
    This script audits the "Restore files and directories" User Rights Assignment to ensure it is restricted only to the Administrators group (*S-1-5-32-544). It automatically updates the local security policy if unauthorized groups or accounts are found.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-15
    Last Modified   : 2026-03-15
    Version         : 1.0
    Severity        : CAT II
    Vuln ID         : V-220982
    STIG-ID         : WN11-UR-000160

.TESTED ON
    Date(s) Tested  : 3/15/2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Pro
    PowerShell Ver. : 5.1.19041.6456

.USAGE  
  PS C:\> .\Fix-RestoreFilesPolicy.ps1 
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as an Administrator. Please launch PowerShell as Admin and try again."
    exit
}

$Privilege    = "SeRestorePrivilege"
$DesiredValue = "*S-1-5-32-544" 
$needsFix     = $false

# Define temporary files for export and database compilation
$TempDir    = $env:TEMP
$ExportFile = Join-Path $TempDir "secpol_export.inf"
$DbFile     = Join-Path $TempDir "secpol_temp.sdb"

# --- AUDIT PHASE ---

Write-Host "Analyzing 'Restore files and directories' User Right Policy..." -ForegroundColor Cyan

# Export the user rights area of the local security policy
secedit /export /cfg $ExportFile /areas USER_RIGHTS | Out-Null

if (-not (Test-Path $ExportFile)) {
    Write-Host "FINDING: Failed to export current security policy for analysis." -ForegroundColor Red
    $needsFix = $true
} else {
    # Read the exported policy
    $Content = Get-Content $ExportFile
    $MatchLine = $Content | Where-Object { $_ -match "^\s*$Privilege\s*=" }

    if ($MatchLine) {
        $CurrentValue = ($MatchLine -split "=", 2)[1].Trim()
        
        if ($CurrentValue -ne $DesiredValue) {
            Write-Host "FINDING: '$Privilege' is granted to unauthorized accounts/groups ($CurrentValue)." -ForegroundColor Red
            $needsFix = $true
        } else {
            Write-Host "COMPLIANT: '$Privilege' is correctly restricted to Administrators ($DesiredValue)." -ForegroundColor Green
            $needsFix = $false
        }
    } else {
        Write-Host "FINDING: '$Privilege' is not defined in the current security policy." -ForegroundColor Red
        $needsFix = $true
    }
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    try {
        $NewContent = @()
        $PrivilegeFound = $false

        # Rebuild the policy file with the corrected value
        if (Test-Path $ExportFile) {
            foreach ($line in $Content) {
                if ($line -match "^\s*$Privilege\s*=") {
                    $NewContent += "$Privilege = $DesiredValue"
                    $PrivilegeFound = $true
                } else {
                    $NewContent += $line
                }
            }

            # If the privilege wasn't defined at all, inject it under [Privilege Rights]
            if (-not $PrivilegeFound) {
                $InsertIndex = [array]::IndexOf($Content, "[Privilege Rights]")
                if ($InsertIndex -ge 0) {
                    $NewContent = $Content[0..$InsertIndex] + "$Privilege = $DesiredValue" + $Content[($InsertIndex+1)..($Content.Count-1)]
                } else {
                    $NewContent += "[Privilege Rights]"
                    $NewContent += "$Privilege = $DesiredValue"
                }
            }

            # Save the corrected policy file using Unicode (required by secedit)
            $NewContent | Out-File -FilePath $ExportFile -Encoding Unicode

            # Import the corrected policy back into Windows
            secedit /configure /db $DbFile /cfg $ExportFile /areas USER_RIGHTS | Out-Null
            
            Write-Host " - REMEDIATION APPLIED: User Right '$Privilege' has been set to $DesiredValue." -ForegroundColor Green
        } else {
            Write-Host " - REMEDIATION FAILED: Export file is missing, cannot apply fix." -ForegroundColor Red
        }
    }
    catch {
        Write-Host " - REMEDIATION FAILED: Failed to apply the fix. Please verify local security policy permissions." -ForegroundColor Red
    }
}

# Clean up temporary files quietly
if (Test-Path $ExportFile) { Remove-Item $ExportFile -Force -ErrorAction SilentlyContinue }
if (Test-Path $DbFile) { Remove-Item $DbFile -Force -ErrorAction SilentlyContinue }
