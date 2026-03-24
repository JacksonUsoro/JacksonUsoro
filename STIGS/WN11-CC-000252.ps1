<#
.SYNOPSIS
    Disables Windows Game Recording and Broadcasting (GameDVR) to ensure system hardening 
    and compliance with security standards.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-03-23
    Last Modified   : 2026-03-23
    Version         : 1.0
    Severity        : Medium (CAT II)
    Vuln ID         : V-253381
    STIG-ID         : WN11-CC-000252

.TESTED ON
    Date(s) Tested  : 2026-03-23
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Enterprise
    PowerShell Ver. : 5.1.22621.1

.USAGE
    PS C:\> .\Disable-GameDVR.ps1
#>

# Define Registry Constants
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$ValueName    = "AllowGameDVR"
$DesiredValue = 0

Write-Host "--- Windows Hardening: Game Recording and Broadcasting ---" -ForegroundColor Cyan

# 1. Ensure the Registry Path exists
if (!(Test-Path $RegistryPath)) {
    Write-Host "[*] Path $RegistryPath not found. Creating..." -ForegroundColor Gray
    try {
        New-Item -Path $RegistryPath -Force | Out-Null
    } catch {
        Write-Error "Failed to create registry path. Please ensure you are running as Administrator."
        return
    }
}

# 2. Check current value
$CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $CurrentValue -or $CurrentValue.$ValueName -ne $DesiredValue) {
    Write-Host "[!] Finding: Policy is not configured correctly." -ForegroundColor Yellow
    
    # 3. Apply the Fix
    try {
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $DesiredValue -Type DWord
        Write-Host "[+] Success: $ValueName set to $DesiredValue." -ForegroundColor Green
    } catch {
        Write-Host "[-] Error: Failed to set registry value." -ForegroundColor Red
    }
} else {
    Write-Host "[+] Compliant: $ValueName is already configured to $DesiredValue." -ForegroundColor Green
}

Write-Host "--- Operation Complete ---" -ForegroundColor Cyan
