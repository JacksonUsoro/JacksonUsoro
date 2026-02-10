<#
.SYNOPSIS
This script checks the running state of Virtualization-Based Security (VBS) via WMI and audits the registry for the correct policy configuration; if the registry settings are missing or incorrect, it enables VBS and sets "Secure Boot" as the required platform security feature.
It requires multiple rounds of restarting the Windows 11 endpoint; the prompts in this script will help.

.NOTES
    Author          : Jackson Usoro
    LinkedIn        : linkedin.com/in/jacksonusoro/
    GitHub          : github.com/jacksonusoro
    Date Created    : 2026-02-10
    Last Modified   : 2026-02-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000070
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE  
  PS C:\> .\WN11-CC-000070.ps1 
#>

# --- CONFIGURATION ---
# Registry path for Device Guard / VBS policy
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

# We look for "EnableVirtualizationBasedSecurity" = 1
$vbsValueName = "EnableVirtualizationBasedSecurity"
$vbsReqValue = 1

# We look for "RequirePlatformSecurityFeatures" = 1 (Secure Boot) OR 3 (Secure Boot + DMA)
# The STIG accepts either. We will enforce 1 (Secure Boot) as the baseline if missing.
$platformValueName = "RequirePlatformSecurityFeatures"
$platformReqMin = 1 

# --- AUDIT PHASE (OPERATIONAL) ---
Write-Host "--- Checking Operational Status ---" -ForegroundColor Cyan

try {
    $dgInfo = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    
    # Check 1: Is VBS Running? (Value 2 = Running)
    if ($dgInfo.VirtualizationBasedSecurityStatus -ne 2) {
        Write-Host "FINDING: VBS is NOT running (Status Code: $($dgInfo.VirtualizationBasedSecurityStatus))." -ForegroundColor Red
        $operationalIssue = $true
    }
    else {
        Write-Host "COMPLIANT: VBS is running." -ForegroundColor Green
    }

    # Check 2: Is Secure Boot Enabled? (Value 2 must be present in the array)
    # The property RequiredSecurityProperties is an array. 2 = Secure Boot.
    if ($dgInfo.RequiredSecurityProperties -notcontains 2) {
        Write-Host "FINDING: Secure Boot is NOT indicated in RequiredSecurityProperties." -ForegroundColor Red
        $operationalIssue = $true
    }
    else {
        Write-Host "COMPLIANT: Secure Boot is active." -ForegroundColor Green
    }
}
catch {
    Write-Host "FINDING: Could not query Win32_DeviceGuard. This system may not support VBS or is a VDI." -ForegroundColor Yellow
    $operationalIssue = $true
}

# --- AUDIT PHASE (REGISTRY) ---
Write-Host "`n--- Checking Registry Configuration ---" -ForegroundColor Cyan
$needsFix = $false

# Check Path
if (-not (Test-Path $registryPath)) {
    Write-Host "FINDING: Registry path is missing." -ForegroundColor Red
    $needsFix = $true
}
else {
    # Check Enable VBS
    $vbsReg = Get-ItemProperty -Path $registryPath -Name $vbsValueName -ErrorAction SilentlyContinue
    if ($null -eq $vbsReg) {
        Write-Host "FINDING: '$vbsValueName' is missing." -ForegroundColor Red
        $needsFix = $true
    }
    elseif ($vbsReg.$vbsValueName -ne $vbsReqValue) {
        Write-Host "FINDING: '$vbsValueName' is $($vbsReg.$vbsValueName). Must be $vbsReqValue." -ForegroundColor Red
        $needsFix = $true
    }

    # Check Platform Security (1 or 3 is acceptable)
    $platformReg = Get-ItemProperty -Path $registryPath -Name $platformValueName -ErrorAction SilentlyContinue
    if ($null -eq $platformReg) {
        Write-Host "FINDING: '$platformValueName' is missing." -ForegroundColor Red
        $needsFix = $true
    }
    elseif ($platformReg.$platformValueName -ne 1 -and $platformReg.$platformValueName -ne 3) {
        Write-Host "FINDING: '$platformValueName' is $($platformReg.$platformValueName). Must be 1 (Secure Boot) or 3 (Secure Boot + DMA)." -ForegroundColor Red
        $needsFix = $true
    }
    else {
        Write-Host "COMPLIANT: Registry configuration is correct." -ForegroundColor Green
    }
}

# --- REMEDIATION PHASE ---
if ($needsFix) {
    Write-Host "`nAttempting to fix Registry Configuration..." -ForegroundColor Yellow

    # Create path if missing
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set EnableVirtualizationBasedSecurity to 1
    Set-ItemProperty -Path $registryPath -Name $vbsValueName -Value $vbsReqValue -Type DWord
    Write-Host " - Set '$vbsValueName' to $vbsReqValue." -ForegroundColor Green

    # Set RequirePlatformSecurityFeatures to 1 (Secure Boot)
    # We default to 1 because we don't know if the hardware supports DMA (3).
    # If it was already 3, logic above would have skipped this block, so we are safe to set 1 here.
    Set-ItemProperty -Path $registryPath -Name $platformValueName -Value $platformReqMin -Type DWord
    Write-Host " - Set '$platformValueName' to $platformReqMin (Secure Boot)." -ForegroundColor Green
    
    Write-Host "NOTE: A reboot is required for VBS changes to take effect." -ForegroundColor Magenta
}
elseif ($operationalIssue -eq $true) {
    Write-Host "`nOBSERVATION: Registry is correct, but VBS is not running. Hardware support (TPM/Virtualization) may be disabled in BIOS/UEFI, or a reboot is pending." -ForegroundColor Magenta
}
