<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/7be3d93c-7637-4a25-81f6-0de56e8fda7e" />


**Date:** February 12, 2026  
**Analyst:** Jackson Usoro  
**Status:** Completed  
**Scenario:** Cyber Range - CorpHealth  
**Target Device:** `ch-ops-wks02` (DeviceID: `fc94078fa6361a8885168e5d31fb0a9d2eead679`)

---

## 📝 Scenario Overview

**Context:** Investigating a cluster of suspicious events on workstation `ch-ops-wks02` occurring between mid-November and early December. The activity involved the `ops.maintenance` service account and the administrative `chadmin` account performing actions outside of standard change windows.

**Initial Indicators:**
* **Time Frame:** Mid-November to Early December (Off-hours).
* **Anomalies:** Manual execution of diagnostic scripts, usage of `curl.exe` to external domains, and encoded PowerShell commands.

---

## 🔎 Investigation & Findings

### 1. Initial Access & Geolocation
**Finding:** The earliest suspicious logon occurred on **November 23, 2025**. The attacker successfully authenticated as `chadmin` from a remote IP address located in **Vietnam**.

* **Timestamp:** `2025-11-23T03:08:31.1849379Z`
* **Source IP:** `104.164.168.17`
* **Region:** Vietnam

#### 🕵️ KQL Hunt Query
```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-01))
| where DeviceName == "ch-ops-wks02"
| where AccountDomain == "ch-ops-wks02"
| where LogonType in ( "RemoteInteractive", "Network", "Batch", "Unlock")
| where isnotempty(RemoteIP)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend Country = tostring(GeoIPInfo.country), 
         City = tostring(GeoIPInfo.city), 
         Latitude = tostring(GeoIPInfo.latitude), 
         Longitude = tostring(GeoIPInfo.longitude)
| order by TimeGenerated asc
| project TimeGenerated, LogonType, RemoteIP, AccountName, Country, City
```
### 2. 🔎 Discovery & Credential Harvesting
Finding: Immediately following the intrusion, the attacker launched explorer.exe and accessed a sensitive file named CH-OPS-WKS02 user-pass.txt. Following this, they ran ipconfig.exe to map the network environment.

First File Accessed: CH-OPS-WKS02 user-pass.txt

Next Account Compromised: ops.maintenance (SID: S-1-5-21-1605642021-30596605-784192815-1000)

#### 🕵️ KQL Hunt Query
```
  // Identify the first file accessed by the attacker
DeviceFileEvents
| where TimeGenerated > todatetime('2025-11-23T03:08:52.8019171Z')
| where InitiatingProcessAccountName == "chadmin"
| where InitiatingProcessId == "5732"
| order by TimeGenerated asc

// Identify the first process launched
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-11-23T03:10:57.3530794Z') 
| where AccountName == "chadmin" 
| order by TimeGenerated asc
```
### 3. Persistence & Privilege Escalation
Finding: The attacker attempted to modify the registry to establish persistence and evade detection. They created a scheduled task tree CorpHealth_A65E64 and utilized encoded PowerShell commands to manipulate access tokens.

Encoded Command: VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAbwBrAGUAbgAtADYARAA1AEUANABFAEUAMAA4ADIAMgA3ACcA

(Decodes to: Write-Output 'token-6D5E4EE08227')
    
#### 🕵️ KQL Hunt Query
```
// Search for Registry modifications
RegistryEvents
| where TimeGenerated < date('2025-12-01') 
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated", "RegistryKeyDeleted") 
| where DeviceName == "ch-ops-wks02" 
| project TimeGenerated, RegistryValueName, RegistryValueData 
| order by TimeGenerated asc

// Search for the specific encoded token command
search "EncodedCommand" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
```    
### 4. Weaponization & C2 Establishment

Finding: The attacker downloaded a reverse shell payload (revshell.exe) using curl from an Ngrok tunnel. They established persistence by placing this executable in the Windows Startup folder.

Payload URL: https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe

Persistence Path: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

C2 Connection: 13.228.171.119:11746

#### 🕵️ KQL Hunt Query
```
  search "revshell.exe"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-12-26))
| where DeviceName == "ch-ops-wks02"
| distinct InitiatingProcessRemoteSessionIP
```

### 5. Staging & Exfiltration
Finding: The attacker staged data in C:\ProgramData and attempted to exclude specific paths from Windows Defender to hide their tools.

Staged Artifact: C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv

File Hash (SHA256): 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

Defender Exclusion Path: C:\ProgramData\Corp\Ops\staging

# 🛡️ Hunt Closure & Analyst Synthesis
  
### Attack Chain Reconstruction:

1. Initial Access: Valid credentials (chadmin) were used via Remote Interactive logon from a suspicious geolocation (Vietnam).

2. Discovery: The attacker immediately located a text file containing passwords (user-pass.txt), leading to lateral movement into the ops.maintenance account.

3. Persistence: Registry keys were modified, and a scheduled task was created. A reverse shell was dropped into the Startup folder to ensure access survived reboots.

4. C2: Usage of ngrok allowed the attacker to bypass standard firewall filtering for ingress/egress.

5. Exfiltration Staging: Inventory files were collected and hashed, likely for exfiltration.

6. Status: Confirmed Compromise. Remediation required for ch-ops-wks02 and rotation of chadmin and ops.maintenance credentials.

### 🛡️ MITRE ATT&CK Mapping

| Tactic | ID | Technique | Observed Context (Evidence) |
| :--- | :--- | :--- | :--- |
| **Initial Access** | **T1078** | Valid Accounts | Attacker authenticated as `chadmin` via Remote Interactive logon from an external IP (`104.164.168.17`). |
| **Execution** | **T1059.001** | PowerShell | Usage of PowerShell with flags `-NoProfile`, `-ExecutionPolicy Bypass`, and `-EncodedCommand` to run scripts. |
| **Persistence** | **T1053.005** | Scheduled Task | Creation of the `CorpHealth_A65E64` scheduled task to maintain access. |
| **Persistence** | **T1547.001** | Registry Run Keys / Startup Folder | Placement of `revshell.exe` in the Windows Startup folder to execute on reboot. |
| **Privilege Escalation**| **T1134** | Access Token Manipulation | Evidence of token impersonation/manipulation in logs (decoded "token-" string) to elevate privileges. |
| **Defense Evasion** | **T1027** | Obfuscated Files or Information | Use of Base64 encoded PowerShell commands to hide the logic of the token manipulation script. |
| **Defense Evasion** | **T1562.001** | Impair Defenses | Attempting to add the path `C:\ProgramData\Corp\Ops\staging` to Windows Defender exclusions. |
| **Defense Evasion** | **T1036.005** | Masquerading: Match Legitimate Name | Naming the reverse shell and csv files (`inventory_6ECFD4DF.csv`) to mimic legitimate CorpHealth operational files. |
| **Credential Access** | **T1552.001** | Credentials in Files | Discovery and reading of the `CH-OPS-WKS02 user-pass.txt` file on the desktop. |
| **Discovery** | **T1016** | System Network Configuration Discovery | Execution of `ipconfig.exe` to map the internal network interface settings. |
| **Command & Control** | **T1105** | Ingress Tool Transfer | Using `curl.exe` to download `revshell.exe` from an external source. |
| **Command & Control** | **T1090.002** | External Proxy | Usage of `ngrok` (identified by the URL `unresuscitating-donnette-smothery.ngrok-free.dev`) to tunnel C2 traffic. |
| **Exfiltration** | **T1074.001** | Data Staged | Staging of the `inventory_6ECFD4DF.csv` file in `C:\ProgramData` prior to potential exfiltration. |
