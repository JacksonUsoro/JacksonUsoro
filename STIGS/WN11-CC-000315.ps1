<#
.SYNOPSIS
    This script ensures that the "AlwaysInstallElevated" policy is disabled in the Windows Registry to prevent standard users from installing software with elevated system privileges.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-09
    Last Modified   : 2026-02-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-CC-000315.ps1 
#>

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$name = "AlwaysInstallElevated"
$value = 0

# Create the key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Host "Created registry path: $registryPath" -ForegroundColor Cyan
}

# Set the DWORD value
Set-ItemProperty -Path $registryPath -Name $name -Value $value -Type DWord

Write-Host "Success: $name has been set to $value." -ForegroundColor Green
