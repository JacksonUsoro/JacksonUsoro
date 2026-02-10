<#
.SYNOPSIS 
  This script enforces "Require secure RPC communication" by setting fEncryptRPCTraffic to 1 in both the Group Policy path and the active RDP-Tcp listener configuration to ensure full compliance.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-10
    Last Modified   : 2026-02-10
    Version         : 3.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000285

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-CC-000285.ps1 
#>

# Define both registry locations
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$systemPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$valueName = "fEncryptRPCTraffic"
$requiredValue = 1
$needsFix = $false

# --- AUDIT PHASE ---

# 1. Check Policy Path
if (-not (Test-Path $policyPath)) {
    Write-Host "FINDING: Policy path '$policyPath' is missing." -ForegroundColor Red
    $needsFix = $true
}
else {
    $policyVal = Get-ItemProperty -Path $policyPath -Name $valueName -ErrorAction SilentlyContinue
    if ($null -eq $policyVal) {
        Write-Host "FINDING: Policy value '$valueName' is missing." -ForegroundColor Red
        $needsFix = $true
    }
    elseif ($policyVal.$valueName -ne $requiredValue) {
        Write-Host "FINDING: Policy '$valueName' is set to $($policyVal.$valueName). It must be $requiredValue." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: Policy '$valueName' is correct." -ForegroundColor Green
    }
}

# 2. Check System/RDP-Tcp Path
if (-not (Test-Path $systemPath)) {
    Write-Host "FINDING: System path '$systemPath' is missing." -ForegroundColor Red
    $needsFix = $true
}
else {
    $systemVal = Get-ItemProperty -Path $systemPath -Name $valueName -ErrorAction SilentlyContinue
    if ($null -eq $systemVal) {
        Write-Host "FINDING: System value '$valueName' is missing in RDP-Tcp." -ForegroundColor Red
        $needsFix = $true
    }
    elseif ($systemVal.$valueName -ne $requiredValue) {
        Write-Host "FINDING: System '$valueName' is set to $($systemVal.$valueName). It must be $requiredValue." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: System '$valueName' is correct." -ForegroundColor Green
    }
}

# --- REMEDIATION PHASE ---

if ($needsFix) {
    Write-Host "`nAttempting to fix..." -ForegroundColor Yellow

    # Fix Policy Path
    if (-not (Test-Path $policyPath)) {
        New-Item -Path $policyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $policyPath -Name $valueName -Value $requiredValue -Type DWord
    Write-Host " - Enforced Policy value set to $requiredValue." -ForegroundColor Green

    # Fix System Path (RDP-Tcp)
    # We generally assume RDP-Tcp exists, but we check just in case.
    if (-not (Test-Path $systemPath)) {
        New-Item -Path $systemPath -Force | Out-Null
    }
    Set-ItemProperty -Path $systemPath -Name $valueName -Value $requiredValue -Type DWord
    Write-Host " - Enforced System (RDP-Tcp) value set to $requiredValue." -ForegroundColor Green
    
    # Refresh Group Policy to ensure the system sees the change.
    Write-Host " - Refreshing Group Policy..." -ForegroundColor Cyan
    Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -NoNewWindow -Wait
}
