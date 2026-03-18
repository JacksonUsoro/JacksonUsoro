<#
.SYNOPSIS
    Ensures 'Configure registry policy processing' is set to 'Enabled' and configured to 
    'Process even if the Group Policy objects have not changed'.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : March 18, 2026
    Last Modified   : March 18, 2026
    Version         : 1.0
    Severity        : CAT II
    Vuln ID         : V-254181
    STIG-ID         : WN11-CC-000090

.TESTED ON
    Date(s) Tested  : March 18, 2026
    Tested By       : Jackson Usoro
    Systems Tested  : Windows 11 Enterprise
    PowerShell Ver. : 5.1.22621.1

.USAGE
    PS C:\> .\Set-GpoRegistryProcessing.ps1
#>

# Variables
$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valName   = "NoGPOListChanges"
$desiredVal = 0

Write-Host "--- Checking Compliance: WN11-CC-000305 ---" -ForegroundColor Cyan

# 1. Verify/Create Registry Key
if (-not (Test-Path $regPath)) {
    Write-Host "[FINDING]: Registry key path does not exist." -ForegroundColor Yellow
    try {
        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Success: Created registry key path." -ForegroundColor Gray
    } catch {
        Write-Error "Failed to create registry key. Ensure you are running as Administrator."
        exit
    }
}

# 2. Check and Set Value
$currentVal = (Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue).$valName

if ($null -eq $currentVal -or $currentVal -ne $desiredVal) {
    Write-Host "[FINDING]: $valName is incorrectly configured." -ForegroundColor Yellow
    Set-ItemProperty -Path $regPath -Name $valName -Value $desiredVal -PropertyType DWord -Force
    Write-Host "[FIXED]: $valName set to $desiredVal (Process even if GPOs have not changed)." -ForegroundColor Green
} 
else {
    Write-Host "[COMPLIANT]: $valName is already set to $desiredVal." -ForegroundColor Green
}

Write-Host "--- Enforcement Complete ---" -ForegroundColor Cyan
