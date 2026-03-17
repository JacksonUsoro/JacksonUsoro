<#
.SYNOPSIS
    This script audits the "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" 
    policy to ensure it is configured to "Require NTLMv2 session security" and "Require 128-bit encryption". 
    It automatically updates the registry if the value is missing or incorrect.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-17
    Last Modified   : 2026-03-17
    Version         : 1.0
    Severity        : CAT II
    Vuln ID         : V-253359
    STIG-ID         : WN11-SO-000220

.TESTED ON
    Date(s) Tested  : 3/17/2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Enterprise
    PowerShell Ver. : 5.1.22621.1

.USAGE  
    PS C:\> .\Fix-NTLMMinServerSec.ps1 
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as an Administrator. Please launch PowerShell as Admin and try again."
    exit
}

# Define Registry Parameters
$RegPath      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$ValueName    = "NTLMMinServerSec"
$DesiredValue = 537395200 # Hex: 0x20080000 (NTLMv2 + 128-bit)
$needsFix     = $false

# --- AUDIT PHASE ---

Write-Host "Analyzing NTLM Minimum Server Security Policy..." -ForegroundColor Cyan

# Check if the registry path exists
if (Test-Path $RegPath) {
    $CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

    if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $DesiredValue) {
        $ActualValue = if ($null -eq $CurrentValue) { "Missing" } else { $CurrentValue.$ValueName }
        Write-Host "FINDING: '$ValueName' is incorrectly configured or missing (Current Value: $ActualValue)." -ForegroundColor Red
        $needsFix = $true
    } else {
        Write-Host "COMPLIANT: '$ValueName' is correctly configured to 0x20080000." -ForegroundColor Green
        $needsFix = $false
    }
} else {
    Write-Host "FINDING: Registry path '$RegPath' does not exist." -ForegroundColor Red
    $needsFix = $true
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "Attempting to fix..." -ForegroundColor Yellow

    try {
        # Ensure the registry key exists
        if (!(Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }

        # Apply the required STIG value
        Set-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -Type DWord -Force
        
        # Verify the fix
        $VerifyValue = Get-ItemProperty -Path $RegPath -Name $ValueName
        if ($VerifyValue.$ValueName -eq $DesiredValue) {
            Write-Host " - REMEDIATION APPLIED: '$ValueName' has been set to 0x20080000 (537395200)." -ForegroundColor Green
        } else {
            throw "Verification failed."
        }
    }
    catch {
        Write-Host " - REMEDIATION FAILED: Failed to apply the registry fix. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "--- Policy Check Complete ---" -ForegroundColor Cyan
