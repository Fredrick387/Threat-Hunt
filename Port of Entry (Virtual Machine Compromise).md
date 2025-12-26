# Threat-Hunting-Port-of-Entry-Jade-Spider-APT-
INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社 SITUATION:   COMPANY: Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia  EVIDENCE AVAILABLE: Microsoft Defender for Endpoint logs


# 🕵️‍♀️ Threat Hunt Report: **Lurker**

Analyst: Fredrick Wilson

Date Completed: 11/25/2025

Environment Investigated: 

Timeframe: 11/20/2025

## 🧠 Scenario Overview

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

---


## Chronological Timeline of Compromise

All events occurred on host **azuki-sl** on **November 20, 2025** (timestamps approximate in UTC/local as shown in logs; primary activity between ~01:37 AM and ~02:11 AM).

| **Time (approx.)**       | **Flag** | **Action Observed**                          | **Key Evidence**                                                                 |
|--------------------------|----------|----------------------------------------------|----------------------------------------------------------------------------------|
| 2025-11-20 01:37 AM      | Flag 18  | Execution - Malicious Script                 | PowerShell script wupdate.ps1 executed to initiate attack chain                  |
| 2025-11-20 01:37 AM      | Flag 10  | Command & Control - Initial Beacon           | Outbound connection from malicious process (svchost.exe) to C2 IP 78.141.196.6 on port 443 |
| 2025-11-20 ~02:05 AM     | Flag 4   | Defense Evasion - Malware Staging Directory  | Creation of hidden directory C:\ProgramData\WindowsCache                         |
| 2025-11-20 02:06 AM      | Flag 7   | Defense Evasion - Download Utility Abuse     | certutil.exe used to download malicious payload                                  |
| 2025-11-20 02:07 AM      | Flag 12  | Credential Access - Credential Theft Tool    | Download and staging of renamed Mimikatz executable mm.exe                       |
| 2025-11-20 02:07 AM      | Flag 8   | Persistence - Scheduled Task Creation        | Scheduled task "Windows Update Check" created                                    |
| 2025-11-20 02:07 AM      | Flag 9   | Persistence - Scheduled Task Target          | Task configured to execute C:\ProgramData\WindowsCache\svchost.exe               |
| 2025-11-20 02:08 AM      | Flag 13  | Credential Access - Memory Extraction        | mm.exe executed with "privilege::debug sekurlsa::logonpasswords exit"            |
| 2025-11-20 ~02:08 AM     | Flag 14  | Collection - Data Staging Archive            | Creation of export-data.zip (and other .zip files like VMAgentLogs.zip) in staging directory |
| 2025-11-20 02:09 AM      | Flag 15  | Exfiltration - Exfiltration Channel          | curl.exe used to upload export-data.zip via HTTPS to Discord                     |
| 2025-11-20 02:10 AM      | Flag 19  | Lateral Movement - Secondary Target          | RDP connection attempted to internal IP 10.1.0.188                               |
| 2025-11-20 02:10 AM      | Flag 20  | Lateral Movement - Remote Access Tool        | mstsc.exe launched for remote desktop to 10.1.0.188                              |
| 2025-11-20 02:11 AM      | Flag 16  | Anti-Forensics - Log Tampering               | wevtutil.exe used to clear Security log (and possibly others)                    |
| 2025-11-20 (post-activity)| Flag 17 | Impact - Persistence Account                 | Hidden local administrator account "support" created and added to Administrators group |
| 2025-11-18 to 2025-11-21 | Flag 1   | Initial Access - Remote Access Source        | RDP connection from external IP 88.97.178.12                                     |
| 2025-11-18 to 2025-11-21 | Flag 2   | Initial Access - Compromised User Account    | Successful logon using account kenji.sato                                        |
| 2025-11-19 to 2025-11-21 | Flag 3   | Discovery - Network Reconnaissance           | arp -a executed to enumerate local network                                       |
| 2025-11-19 to 2025-11-21 | Flag 5   | Defense Evasion - File Extension Exclusions  | 3 file extensions added to Windows Defender exclusions                           |
| 2025-11-19 to 2025-11-21 | Flag 6   | Defense Evasion - Temporary Folder Exclusion | Exclusion added for Temp folder                                                  |
| 2025-11-19 to 2025-11-21 | Flag 11  | Command & Control - C2 Communication Port     | Persistent C2 traffic over port 443                                              |

**Notes:**
- One of my first threat hunts, and I didn't record the timestamps correctly.

### Starting Point – 


**Identified System:**
michaelvm


### 🪪 Flag 1 – INITIAL ACCESS - Remote Access Source

**Objective:**
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**What to Hunt:**
Query logon events for interactive sessions from external sources during the incident timeframe.

**Identified Activity:**
88.97.178.12 is the source IP address of the Remote Desktop Protocol Connection

**Why It Matters:**
This PowerShell command represents the earliest deviation from baseline behavior on the compromised host michaelvm. The use of -ExecutionPolicy Bypass indicates a deliberate attempt to circumvent PowerShell script restrictions — a common tactic for initial payload deployment.

**KQL Query Used:**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName,  RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/0a155b6a-d56c-477c-9cf5-6f8f08e15e52" />



### 🛰️ Flag 2 – INITIAL ACCESS - Compromised User Account

**Objective:**
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts, including password resets and privilege reviews.

**What to Hunt:**
Focus on the account that authenticated during the suspicious remote access session. Cross-reference the logon event timestamp with the external IP connection.

**Identified User Account:**
kenji.sato

**Why It Matters:**


**KQL Query Used**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName,  RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/346167c5-d6b6-4374-a139-d1db62b494b6" />



### 📄 Flag 3 – DISCOVERY - Network Reconnaissance

**Objective:**
Look for commands that reveal local network devices and their hardware addresses.

**What to Hunt:**
Look for file access involving keywords like board, financial, or crypto — especially in user folders. Check DeviceProcessEvents for network enumeration utilities executed after initial access.

**Identified Command:**
"ARP.EXE" -a

**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1709" height="488" alt="image" src="https://github.com/user-attachments/assets/2321e140-cf3b-4c28-ae5a-91a90feb3a6c" />



### ⏱️ Flag 4 – DEFENCE EVASION - Malware Staging Directory

**Objective:**
Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**What to Hunt:**
Search for newly created directories in system folders that were subsequently hidden from normal view. Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

**PRIMARY Staging Directory Found:**
C:\ProgramData\WindowsCache
Nov 20, 2025 2:05:30 AM

**Why It Matters:**



**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "powershell"
```
<img width="1679" height="432" alt="image" src="https://github.com/user-attachments/assets/1dd10cdd-be4d-4e5c-af6d-463cdd687371" />



### ⚙️ Flag 5 – DEFENCE EVASION - File Extension Exclusions

**Objective:**
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**What to Hunt:**
Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extension. Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

**Identified File Extension Excluded:**
3
powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command "& {$OutputEncoding = [Console]::OutputEncoding =[System.Text.Encoding]::UTF8;$scriptFileStream = [System.IO.File]::Open('C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);$calculatedHash = Microsoft.PowerShell.Utility\Get-FileHash 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1' -Algorithm SHA256;if (!($calculatedHash.Hash -eq '25fda4c27044455e664e8c26cdd2911117493a9122c002cd9462a9ce9c677f22')) { exit 323;}; . 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1' }"

**Why It Matters:**


**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessParentFileName contains "sense"
```
<img width="1668" height="249" alt="image" src="https://github.com/user-attachments/assets/e4227628-f81c-4c71-8509-d8867114398e" />
<img width="1678" height="435" alt="image" src="https://github.com/user-attachments/assets/d86c2602-327d-4996-a572-65bb1b582930" />



### 💾 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

**Objective:**
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**What to Hunt:**
Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field. Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field. The registry key contains "Exclusions\Paths" under Windows Defender configuration.

**Identified Temporary Folder:**

C:\Users\KENJI~1.SAT\AppData\Local\Temp

**Why It Matters:**

**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"

```

<img width="1677" height="402" alt="image" src="https://github.com/user-attachments/assets/d19ed60a-9ddb-45e7-84b9-1641deef37f7" />



### 📎 Flag 7 – DEFENCE EVASION - Download Utility Abuse

**Objective:**
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**What to Hunt:**
Look for built-in Windows tools with network download capabilities being used during the attack. Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

**Identified Command**
certutil.exe
Nov 20, 2025 2:06:58 AM
**Why It Matters:**


KQL Query Used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "//"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```

<img width="555" height="529" alt="image" src="https://github.com/user-attachments/assets/e2690950-e773-44b1-b292-40d35f1b3920" />




### 🗂️ Flag 8 – Scheduled Task Name

**Objective:**
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**What to Hunt:**
Search for scheduled task creation commands executed during the attack timeline. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

**Identified Scheduled Task:**
Windows Update Check
Nov 20, 2025 2:07:46 AM
**Why It Matters:**

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="545" height="425" alt="image" src="https://github.com/user-attachments/assets/6d53958a-2f9e-4841-bb1d-8ee5676b99c7" />



### 🗝️ Flag 9 – PERSISTENCE - Scheduled Task Target

**Objective:**
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**What to Hunt:**
Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command.

**Identified Executable Path within Scheduled Task:**
C:\ProgramData\WindowsCache\svchost.exe
Nov 20, 2025 2:07:46 AM

**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```

<img width="839" height="69" alt="image" src="https://github.com/user-attachments/assets/b8e1a986-c3c3-4d61-b6e4-f59b5ab802b3" />



### ⏰ Flag 10 – COMMAND & CONTROL - C2 Server Address

**Objective:**
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**What to Hunt:**
Analyse network connections initiated by the suspicious executable shortly after it was downloaded. Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

**Identified Server IP:**
78.141.196.6
Nov 20, 2025 1:37:26 AM

**Why It Matters:**

**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"

```

<img width="1703" height="101" alt="image" src="https://github.com/user-attachments/assets/5cd5847a-c4fb-4805-978c-697945ae0897" />




### 🧭 Flag 11 – COMMAND & CONTROL - C2 Communication Port

**Objective:**
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**What to Hunt:**
Examine the destination port for outbound connections from the malicious executable. Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.

**Identified Destination Port:**
443

**Why It Matters:**


**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```
<img width="1672" height="391" alt="image" src="https://github.com/user-attachments/assets/b0ef8b80-d0df-406c-ab5b-0bc61d8560a8" />



### ⏱️ Flag 12 – CREDENTIAL ACCESS - Credential Theft Tool

**Objective:**
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**What to Hunt:**
Look for executables downloaded to the staging directory with very short filenames. Search for files created shortly before LSASS memory access events.

**Identified Executable:**
mm.exe
Nov 20, 2025 2:07:22 AM
**Why It Matters:**


**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FolderPath contains "cache"
```
<img width="1692" height="425" alt="image" src="https://github.com/user-attachments/assets/8a4cf6e5-233d-4a59-858a-76f01b04313c" />



### 📂 Flag 13 – CREDENTIAL ACCESS - Memory Extraction Module

**Objective:**
Reveal which specific document the attacker targeted on the second host.

**What to Hunt:**
Examine the command line arguments passed to the credential dumping tool. Look for module::command syntax in the process command line or output redirection.

**Identified Permissions:**

"mm.exe" privilege::debug sekurlsa::logonpasswords exit

Nov 20, 2025 2:08:26 AM

**Why It Matters:**


**KQL Queries Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where FileName contains "mm.exe"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession

```
<img width="1713" height="163" alt="image" src="https://github.com/user-attachments/assets/36b8ab65-61e3-4963-956e-604ebc04d23f" />




### ☁️ Flag 14 – COLLECTION - Data Staging Archive

**Objective:**
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**What to Hunt:**
Search for ZIP file creation in the staging directory during the collection phase. Look for Compress-Archive commands or examine files created before exfiltration activity.

**Compressed archives for Data Exfiltration:**

**Why It Matters:**

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FileName contains ".zip"
```

<img width="1096" height="161" alt="image" src="https://github.com/user-attachments/assets/79729a8a-c67f-4b52-89b3-68067296c30b" />


### 🌐 Flag 15 – EXFILTRATION - Exfiltration Channel

**Objective:**
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**What to Hunt:**
Analyse outbound HTTPS connections and file upload operations during the exfiltration phase. Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

**Cloud Service:**
discord
Nov 20, 2025 2:09:21 AM

**Why It Matters:**


**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```

<img width="624" height="580" alt="image" src="https://github.com/user-attachments/assets/f56ec8bb-3736-4c01-aa1d-553952a05961" />




### 🧬 Flag 16 – ANTI-FORENSICS - Log Tampering

**Objective:**
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**What to Hunt:**
Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions and identify which log was cleared first.

**Cleared Windows Event Log:**
Security
Nov 20, 2025 2:11:39 AM

**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "wev"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1641" height="358" alt="image" src="https://github.com/user-attachments/assets/ed10b702-1075-4e29-8990-331d3b900ba8" />

<img width="1677" height="330" alt="image" src="https://github.com/user-attachments/assets/182dccd6-c8af-47c5-b89a-318df8f1c4a4" />



### 🧹 Flag 17 – IMPACT - Persistence Account

**Objective:**
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**What to Hunt:**
Search for account creation commands executed during the impact phase. Look for commands with the /add parameter followed by administrator group additions.

**Hidden Username:**
support

**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" height="135" alt="image" src="https://github.com/user-attachments/assets/656c2f22-51e3-44be-90d7-dee068d70c56" />




---

### 🧹 Flag 18 – EXECUTION - Malicious Script

**Objective:**
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**What to Hunt:**
Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

**Found PowerShell Script to Start Attack Chain:**
Nov 20, 2025 1:37:40 AM
wupdate.ps1
**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" height="135" alt="image" src="https://github.com/user-attachments/assets/656c2f22-51e3-44be-90d7-dee068d70c56" />




---

### 🧹 Flag 19 – LATERAL MOVEMENT - Secondary Target

**Objective:**
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**What to Hunt:**
Examine the target system specified in remote access commands during lateral movement.Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.
**IP Address Target:**
10.1.0.188

Nov 20, 2025 2:10:41 AM

**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1670" height="384" alt="image" src="https://github.com/user-attachments/assets/4381ab9d-2771-4b70-9a8f-e29989b3e882" />





---

### 🧹 Flag 20 – LATERAL MOVEMENT - Remote Access Tool

**Objective:**
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.
**What to Hunt:**
Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.
**Remote Access Tool:**
mstsc.exe
Nov 20, 2025 2:10:41 AM


**Why It Matters:**


**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1699" height="388" alt="image" src="https://github.com/user-attachments/assets/d0d87a69-2271-4ccb-b649-47e96ebb6bdb" />






---
## 🔍 Timeline of Events

| **Timestamp (UTC)**                | **Event**                                                         | **Device**  | **Details**                                                      |
| ---------------------------------- | ----------------------------------------------------------------- | ----------- | ---------------------------------------------------------------- |
| **2025-06-14 15:38:45**            | First activity detected on `michaelvm`                            | michaelvm   | Initial signs of temp folder execution                           |
| **2025-06-15 (evening)**           | Scheduled Task created                                            | michaelvm   | `MarketHarvestJob` set to run client\_update.hta with PowerShell |
| **2025-06-16 05:56:59**            | Reconnaissance via `net group "Domain Admins"` command            | michaelvm   | SHA256: `badf4752413...` initiated from PowerShell               |
| **2025-06-16 06:12:28**            | Sensitive document accessed: `QuarterlyCryptoHoldings.docx`       | michaelvm   | From folder `Documents\BoardMinutes`                             |
| **2025-06-16 06:32:09**            | ADS-style DLL `investor_report.dll` dropped                       | michaelvm   | SHA1: `801262e122db...` in Temp folder                           |
| **2025-06-16 06:41:24**            | Registry persistence established via autorun key                  | michaelvm   | Key: `HKCU\...\Run` with value `WalletUpdater`                   |
| **2025-06-16 08:32:34**            | Lateral movement command to `centralsrvr` executed via `schtasks` | michaelvm   | Command targets `centralsrvr` using credentials                  |
| **2025-06-17 03:00:49**            | Last lateral movement command confirmed                           | michaelvm   | Final pivot toward `centralsrvr`                                 |
| **2025-06-17 22:23:24**            | Sensitive document accessed on `centralsrvr`                      | centralsrvr | `QuarterlyCryptoHoldings.docx` accessed remotely by `MICHA3L`    |
| **2025-06-17 22:23:28 – 22:23:31** | Data exfiltration attempts to: Google Drive, Dropbox, Pastebin    | centralsrvr | MD5: `2e5a8590cf68...`                                           |
| **2025-06-18 10:52:33**            | Event log clearing with `wevtutil cl Security`                    | centralsrvr | Attempt to wipe forensic evidence                                |
| **2025-06-18 10:52:59**            | PowerShell downgrade to v2 for evasion                            | centralsrvr | Likely to disable ScriptBlock/AMSI logging                       |


---

## 🧩 MITRE ATT&CK Mapping

| **Flag/Event**                       | **Tactic** (TA#)                | **Technique** (T#)                                      | **Details**                                                         |
| ------------------------------------ | ------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------- |
| **Initial PowerShell Execution**     | Execution (TA0002)              | T1059.001 – PowerShell                                  | Bypass flag used to execute `.ps1` script from user directory       |
| **Recon: Domain Admins Query**       | Discovery (TA0007)              | T1069.002 – Domain Groups                               | Recon via `net group "Domain Admins"` from PowerShell               |
| **Sensitive File Access**            | Collection (TA0009)             | T1005 – Data from Local System                          | Accessed `QuarterlyCryptoHoldings.docx` in `Documents\BoardMinutes` |
| **bitsadmin.exe Download**           | Command and Control (TA0011)    | T1105 – Ingress Tool Transfer                           | Used `bitsadmin.exe` to download a payload stealthily               |
| **Payload Drop: ledger\_viewer.exe** | Execution (TA0002)              | T1204.002 – User Execution: Malicious File              | Fake financial viewer dropped in Temp folder                        |
| **HTA Abuse via mshta.exe**          | Execution (TA0002)              | T1218.005 – mshta                                       | Used to execute malicious `client_update.hta`                       |
| **ADS DLL Drop**                     | Defense Evasion (TA0005)        | T1564.004 – Hidden Files and Directories: ADS           | DLL (`investor_report.dll`) mimicked hidden stream behavior         |
| **Registry Persistence**             | Persistence (TA0003)            | T1547.001 – Registry Run Keys                           | Added `WalletUpdater` entry to HKCU autorun                         |
| **Scheduled Task Creation**          | Persistence (TA0003), Execution | T1053.005 – Scheduled Task/Job: Scheduled Task          | `MarketHarvestJob` created for logon persistence                    |
| **Lateral Movement via schtasks**    | Lateral Movement (TA0008)       | T1021.003 – Remote Services: Windows Admin Shares       | schtasks used with `/S` to pivot to `centralsrvr`                   |
| **Remote Document Access**           | Collection (TA0009)             | T1213 – Data from Information Repositories              | Remote access to same financial doc from second host                |
| **Exfiltration to Pastebin/Cloud**   | Exfiltration (TA0010)           | T1048.003 – Exfiltration Over Alternative Protocol      | Exfil to Google Drive, Dropbox, Pastebin                            |
| **PowerShell Downgrade**             | Defense Evasion (TA0005)        | T1059.001 + T1562.001 – Input Capture + Disable Logging | Downgrade to PowerShell v2 to evade modern logging                  |
| **Log Clearing**                     | Defense Evasion (TA0005)        | T1070.001 – Clear Windows Event Logs                    | `wevtutil.exe cl Security` used prior to exit                       |


---

## 💠 Diamond Model Summary

| **Feature**        | **Details**                                                                                                                                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Adversary**      | - Likely a hands-on-keyboard threat actor or red team simulation using stealthy, multi-stage execution.<br>- Demonstrated knowledge of LOLBins, evasion tactics, and lateral movement.                                                   |
| **Infrastructure** | - External command & control via cloud services: `drive.google.com`, `dropbox.com`, `pastebin.com`, `104.22.69.199`.<br>- Delivery and execution through living-off-the-land binaries (`bitsadmin.exe`, `mshta.exe`, `wevtutil.exe`).    |
| **Capability**     | - PowerShell scripts with execution policy bypass and version downgrade for AMSI evasion.<br>- Recon tools (`net group`), ADS payloads, scheduled tasks, and registry persistence.<br>- Data exfiltration over alternative web channels. |
| **Victim**         | - Initial: `michaelvm` (entry point)<br>- Lateral: `centralsrvr`<br>- Targeted files: `QuarterlyCryptoHoldings.docx` on both machines<br>- Sensitive folder paths and scheduled tasks abused for persistence and access.                 |
---
## 💡 Key Relationships:
- Adversary used capability (PowerShell, LOLBins, recon, persistence) on victim (michaelvm, then centralsrvr)

- Adversary leveraged infrastructure (public cloud services + native tools) to exfiltrate data

- Capability enabled movement from initial compromise to expansion and cleanup

---

## ✅ Conclusion

The Lurker threat scenario exposed a stealthy multi-phase intrusion that began with the abuse of PowerShell and native Windows tools and evolved into a targeted data exfiltration campaign. The adversary executed with precision, leveraging legitimate binaries (LOLBins), social engineering payloads, registry and scheduled task persistence, and evasion techniques such as PowerShell version downgrades and event log clearing.

Through forensic analysis of process events, file reads, registry changes, and network activity, we successfully reconstructed the adversary’s kill chain across two compromised systems: michaelvm and centralsrvr.

---

## 🧠 Lessons Learned
- **Initial Access Often Mimics Legitimate Use**
  
 PowerShell activity from user folders with policy bypass flags should raise alerts even when they look routine.

- **LOLBin Abuse Is a Persistent Risk**

 Adversaries increasingly favor native tools (bitsadmin, mshta, wevtutil) to avoid detection by EDRs.

- **Persistence Tactics Are Layered**

 Registry keys and scheduled tasks were both used, ensuring the attacker maintained control across reboots.

- **Cloud Services Can Be Used for Exfiltration**

 Dropbox, Google Drive, and Pastebin were all leveraged for outbound data transfers, evading traditional filters.

- **Downgrade Attacks Undermine Modern Logging**

 PowerShell downgrade to Version 2 disabled script block logging and AMSI defenses.

- **Cleaning Logs ≠ Cleaning Up**

 Even though logs were cleared, timestamps and forensic remnants allowed a full attack reconstruction.

---

## 🛡 Remedial Actions
1. **Enhance PowerShell Monitoring**

- Enforce Constrained Language Mode

- Block execution of PowerShell v2 where possible

- Enable deep script block logging and central collection

2. **Detect and Block LOLBin Abuse**

- Alert on uncommon use of mshta.exe, bitsadmin.exe, and wevtutil.exe

- Use allow-listing to limit legitimate LOLBin usage

3. **Harden Persistence Defenses**

- Monitor HKCU\Software\Microsoft\Windows\CurrentVersion\Run

- Detect suspicious scheduled task creation by non-admin users

4. **Restrict Outbound Access to Known Cloud Services**

- Block access to file-sharing platforms not explicitly approved (e.g., Dropbox, Pastebin)

- Use CASB or DLP to inspect cloud-bound traffic

5. **Implement Lateral Movement Protections**

- Audit schtasks.exe usage with remote /S flag

- Require MFA and remove excessive admin privileges

6. **Automate Log Integrity Verification**

- Set alerts for wevtutil cl activity

- Forward logs to a secure, remote SIEM that is tamper-resistant




### 🚩 Flag 1 – INITIAL ACCESS - Remote Access Source

🎯 **Objective:**  
Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

📌 **Finding:**  
Source IP of RDP connection: `88.97.178.12`

🔍 **Evidence:**

| Field       | Value                        |
|-------------|------------------------------|
| Host        | azuki-sl                     |
| Timestamp   | 2025-11-18 .. 2025-11-21    |
| ActionType  | LogonSuccess                 |
| AccountName | [varies]                     |
| RemoteIP    | 88.97.178.12                 |
| RemoteIPType| External                     |
| DeviceName  | azuki-sl                     |

💡 **Why it matters:**  
This shows *how the attacker first entered the environment*. An external RDP login is a classic initial access vector. The attacker also executed PowerShell using `-ExecutionPolicy Bypass`, suggesting intentional evasion of safeguards.  
MITRE ATT&CK: **TA0001 – Initial Access**, **T1078 – Valid Accounts**.

🔧 **KQL Query Used**
    DeviceLogonEvents
    | where DeviceName == "azuki-sl"
    | where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
    | where RemoteIP contains "."
    | where ActionType == "LogonSuccess"
    | project Timestamp, ActionType, AccountName, RemoteIP, RemoteIPType, RemoteDeviceName
    | order by Timestamp asc

🖼️ Screenshot  
Insert screenshot here

🛠️ **Detection Recommendation**
```
    DeviceLogonEvents
    | where ActionType == "LogonSuccess" and RemoteIPType == "External"
    | summarize Count=count() by AccountName, RemoteIP, DeviceName
    | where Count > 0
```
```md
### 🚩 Flag 2 – INITIAL ACCESS - Compromised User Account

🎯 **Objective:**  
Identifying which credentials were compromised determines the scope of unauthorized access and guides remediation efforts, including password resets and privilege reviews.

📌 **Finding:**  
Compromised user account: `kenji.sato`

🔍 **Evidence:**

| Field       | Value                        |
|-------------|------------------------------|
| Host        | azuki-sl                     |
| Timestamp   | 2025-11-18 .. 2025-11-21    |
| ActionType  | LogonSuccess                 |
| AccountName | kenji.sato                   |
| RemoteIP    | [varies]                     |
| DeviceName  | azuki-sl                     |

💡 **Why it matters:**  
Compromised credentials allow attackers to move laterally and access sensitive systems without triggering typical initial access alerts. Monitoring these accounts can prevent deeper compromise.  
MITRE ATT&CK: **TA0001 – Initial Access**, **T1078 – Valid Accounts**.

🔧 **KQL Query Used**
    DeviceLogonEvents
    | where DeviceName == "azuki-sl"
    | where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
    | where RemoteIP contains "."
    | where ActionType == "LogonSuccess"
    | project Timestamp, ActionType, AccountName, RemoteIP, RemoteIPType, RemoteDeviceName
    | order by Timestamp asc

🖼️ Screenshot  
Insert screenshot here

🛠️ **Detection Recommendation**
```mdat
    DeviceLogonEvents
    | where ActionType == "LogonSuccess"
    | summarize Count=count() by AccountName, DeviceName
    | where Count > 3
```
```md
### 🚩 Flag 3 – DISCOVERY - Network Reconnaissance

🎯 **Objective:**  
Detect commands that reveal local network devices and their hardware addresses, which indicate reconnaissance activity.

📌 **Finding:**  
Command executed: `"ARP.EXE" -a`

🔍 **Evidence:**

| Field                  | Value                       |
|------------------------|-----------------------------|
| Host                   | azuki-sl                    |
| Timestamp              | 2025-11-19 .. 2025-11-21   |
| DeviceName             | azuki-sl                    |
| ProcessCommandLine      | "ARP.EXE" -a               |
| FolderPath             | [varies]                    |
| AccountName            | [varies]                    |
| IsProcessRemoteSession | [true/false]                |

💡 **Why it matters:**  
ARP scans indicate the attacker is mapping internal networks, which is critical for planning lateral movement. Detecting these early prevents deeper penetration.  
MITRE ATT&CK: **TA0007 – Discovery**, **T1046 – Network Service Scanning**.

🔧 **KQL Query Used**
    DeviceProcessEvents
    | where DeviceName == "azuki-sl"
    | where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
    | project Timestamp, DeviceName, ProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession

🖼️ Screenshot  
Insert screenshot here

🛠️ **Detection Recommendation**
```mdat
    DeviceProcessEvents
    | where ProcessCommandLine contains "ARP.EXE"
    | summarize Count=count() by DeviceName, AccountName
    | where Count > 1
```
