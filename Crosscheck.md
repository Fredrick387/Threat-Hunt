
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/a4a09fc7-07b8-419e-b324-50670881501f"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>






# 🛡️ Threat Hunt Report – <Hunt Name>

---

## 📌 Executive Summary

<Brief, high-level overview of the threat hunt.  
Answer what happened, why it matters, and what was discovered in 3–4 sentences.>

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** <Placeholder>  
- **Data Sources:** <Placeholder>  
- **Timeframe:** <YYYY-MM-DD → YYYY-MM-DD>
- **Link:** https://docs.google.com/forms/d/e/1FAIpQLSeUTjLMNcPwpjvgDnGC-MJOE7EaBm4ObwNeyhlfl66Di8o6cQ/viewform?usp=header

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | <Placeholder> | <Placeholder> | <Placeholder> |
| 2 | <Placeholder> | <Placeholder> | <Placeholder> |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Initial Access via Compromised Service Account</strong></summary>

### 🎯 Objective
Establish initial foothold on target endpoint using compromised credentials.

### 📌 Finding
ProcessCreated event observed on sys1-dept endpoint initiated by account 5y51-d3p7. The activity represents the first recorded action in the attack chain, indicating successful credential compromise and initial access to the environment.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/1/2025, 3:13:33.708 AM |
| ActionType | ProcessCreated |
| DeviceId | 1d0e12b505d61c7eb1f1fd7842d905c99f6ae26a |
| Initiating Account | sys1-dept\5y51-d3p7 |
| AccountSid | S-1-5-21-805396643-3920266184-3816603331-500 |
| TenantId | 60c7f53e-249a-4077-b68e-55a4ae877d7c |

### 💡 Why it matters
This event marks the initial access phase of the intrusion, aligning with **MITRE ATT&CK T1078 (Valid Accounts)**. The use of account 5y51-d3p7 suggests credential theft or compromise occurred prior to this activity. The timing (early morning hours) and the fact this is the earliest observed event in the timeline indicates this is the attacker's entry point. The AccountSid ending in -500 indicates a built-in Administrator account, representing high-privilege access from the start of the compromise.

### 🖼️ Screenshot
<img width="883" height="225" alt="image" src="https://github.com/user-attachments/assets/78aeda9a-e124-4750-9002-05abdbd14c65" />


### 🛠️ Detection Recommendation
**Hunting Tip:**  
Pivot on the compromised account (5y51-d3p7) across all logs to identify the full scope of unauthorized activity. Query authentication logs (IdentityLogonEvents) to determine where and when this account authenticated prior to this event. Look for anomalous logon patterns such as impossible travel, unusual source IPs, or logons outside normal business hours. Correlate process creation events with this account to map the attack chain progression.

</details>


---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Remote Session Source Attribution</strong></summary>

### 🎯 Objective
Identify the remote session source information tied to the initiating access on the first endpoint.

### 📌 Finding
Remote session activity detected on sys1-dept originating from external IP address 192.168.0.110. The session was established under the compromised account 5y51-d3p7, with the `IsInitiatingProcessRemoteSession` flag confirming remote execution context. This metadata reveals the attacker's source infrastructure used to access the compromised endpoint.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 1:24:53.664 AM |
| InitiatingProcessAccountName | 5y51-d3p7 |
| IsInitiatingProcessRemoteSession | true |
| LocalIP | 10.0.0.12 |
| RemoteIPType | Public |
| RemoteIP | 192.168.0.110 |

### 💡 Why it matters
This finding maps to **MITRE ATT&CK T1021 (Remote Services)** and provides critical attribution intelligence. The remote IP 4.150.155.223 represents the attacker's infrastructure or compromised staging system used to access the environment. Remote session metadata is essential for identifying the attack origin, blocking active threat actor infrastructure, and correlating activity across multiple incidents. The public IP classification confirms external access rather than lateral movement from another internal system. This data point enables defenders to pivot across all telemetry sources to identify the full scope of connections from this malicious source.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceNetworkEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated >= startTime + 24h
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, IsInitiatingProcessRemoteSession, LocalIP, RemoteIPType, RemoteIP
```

### 🖼️ Screenshot
<img src="uploads/1769913464418_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**  
Pivot on the source IP 4.150.155.223 across all network telemetry to identify additional compromised accounts or systems. Query IdentityLogonEvents and DeviceLogonEvents for authentication attempts from this IP. Hunt for remote session indicators (`IsInitiatingProcessRemoteSession == true`) combined with external IPs to detect similar attack patterns. Correlate with threat intelligence feeds to determine if this IP is known malicious infrastructure. Check firewall logs for persistence of connections from this source and identify any other internal systems contacted.

</details>

---


<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Support Script Execution Confirmation</strong></summary>

### 🎯 Objective
Confirm execution of a support-themed PowerShell script from a user-accessible directory.

### 📌 Finding
PowerShell execution detected on sys1-dept with an execution policy bypass executing a script named "PayrollSupportTool.ps1" from the user's Downloads directory. The command line indicates deliberate evasion of PowerShell security controls to execute the malicious payload.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:07:15.565 AM |
| AccountName | 5y51-d3p7 |
| ProcessCommandLine | "powershell.exe" -ExecutionPolicy Bypass -File C:\users\5y51-D3p7\Downloads\PayrollSupportTool.ps1 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)** and **T1204.002 (User Execution: Malicious File)**. The use of `-ExecutionPolicy Bypass` is a classic defense evasion technique that circumvents PowerShell's built-in script execution restrictions. The script name "PayrollSupportTool.ps1" follows social engineering naming conventions designed to appear legitimate. Execution from the Downloads folder indicates the script was likely delivered via phishing, malicious download, or copied during the remote session. This marks a critical escalation point where the attacker transitions from remote access to executing custom tooling on the compromised system.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### 🖼️ Screenshot
<img src="uploads/1769915136997_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for PowerShell executions with `-ExecutionPolicy Bypass`, `-ep bypass`, or `-exec bypass` flags across the environment. Query DeviceFileEvents to identify when PayrollSupportTool.ps1 was created or modified to determine delivery method. Extract and analyze the script contents from endpoint or backup sources. Pivot on Downloads directory executions combined with script file extensions (.ps1, .bat, .vbs, .js) to identify similar malicious script activity. Look for child processes spawned by this PowerShell execution to map post-exploitation activity.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: System Reconnaissance Initiation</strong></summary>

### 🎯 Objective
Identify the first reconnaissance action used to gather host and user context.

### 📌 Finding
Execution of whoami.exe detected on sys1-dept with the /all parameter, representing the attacker's initial reconnaissance command to enumerate security context. This command provides comprehensive information about the current user's privileges, group memberships, and security identifiers.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:12:03.789 AM |
| DeviceName | sys1-dept |
| ProcessCommandLine | "whoami.exe" /all |

### 💡 Why it matters
This activity aligns with **MITRE ATT&CK T1033 (System Owner/User Discovery)** and **T1069 (Permission Groups Discovery)**. The `whoami /all` command is a standard post-exploitation reconnaissance technique used to assess current privilege level, group memberships, security tokens, and integrity levels. This information guides the attacker's next moves, including privilege escalation paths, lateral movement targets, and understanding what actions the compromised account can perform. The timing approximately 5 minutes prior to the PowerShell script execution suggests this was executed manually by the attacker to assess the environment before deploying additional tooling.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has_any ("whoami", "net user", "net group", "query user")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="uploads/1769915438765_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for native Windows reconnaissance binaries (whoami.exe, net.exe, ipconfig.exe, systeminfo.exe, tasklist.exe) executed within remote sessions or by service accounts. Look for rapid sequential execution of multiple discovery commands within short time windows, indicating scripted or manual enumeration. Correlate whoami execution with subsequent privilege escalation attempts or lateral movement activity. Query for command-line parameters like /all, /priv, or /groups that indicate thorough enumeration. Stack count executions by AccountName to identify accounts performing abnormal discovery activity.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Sensitive Bonus-Related File Exposure</strong></summary>

### 🎯 Objective
Identify the first sensitive year-end bonus-related file that was accessed during exploration.

### 📌 Finding
FileCreated event detected on sys1-dept for a file named "BonusMatrix_Draft_v3.xlsx.lnk" initiated by Explorer.exe under the compromised account. This shortcut file indicates the attacker discovered and interacted with sensitive compensation data, creating a link that could be used for later access or as evidence of file discovery.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:24:42.960 AM |
| ActionType | FileCreated |
| FileName | BonusMatrix_Draft_v3.xlsx.lnk |
| InitiatingProcess | Explorer.exe |
| InitiatingProcessAccountName | 5y51-d3p7 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1083 (File and Directory Discovery)** and indicates progression toward **T1005 (Data from Local System)**. The creation of a .lnk (shortcut) file suggests interactive browsing behavior through Windows Explorer, indicating hands-on-keyboard activity rather than automated tooling. The file name "BonusMatrix_Draft_v3.xlsx" clearly contains sensitive compensation information that would be high-value for corporate espionage, insider threats, or ransomware operators seeking leverage. The "Draft_v3" naming convention suggests this is working documentation that may contain unredacted or preliminary bonus allocation data. This marks the transition from system reconnaissance to targeted data discovery.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-10T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessUniqueId
```

### 🖼️ Screenshot
<img width="782" height="221" alt="image" src="https://github.com/user-attachments/assets/09c92ac0-7dae-4acd-8c6e-391ffd6bc749" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Query DeviceFileEvents for access to files containing sensitive keywords (bonus, salary, compensation, payroll, executive) by the compromised account. Look for FileCreated actions involving .lnk files as indicators of interactive file browsing. Pivot to identify the full path of the original BonusMatrix_Draft_v3.xlsx file and check for subsequent FileRead, FileModified, or FileCopied events. Hunt for file staging activity where sensitive documents are copied to temporary directories or compressed into archives. Review network telemetry for potential exfiltration of this file to external IPs or cloud storage services.

</details>
---

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Data Staging Activity Confirmation</strong></summary>

### 🎯 Objective
Confirm that sensitive data was prepared for movement by staging into an export/archive output.

### 📌 Finding
FileCreated event detected for "export_stage.zip" on sys1-dept, initiated by powershell.exe under the compromised account. This archive file represents data staging activity where the attacker packaged sensitive files for exfiltration, confirming progression from discovery to collection and preparation for data theft.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:10.682 AM |
| ActionType | FileCreated |
| FileName | export_stage.zip |
| InitiatingProcessCommandLine | "powershell.exe" |
| InitiatingProcessId | 5632 |
| InitiatingProcessUniqueId | 2533274790396713 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1560.001 (Archive Collected Data: Archive via Utility)** and **T1074.001 (Data Staged: Local Data Staging)**. The creation of a ZIP archive with the explicit name "export_stage" demonstrates clear intent to exfiltrate data. Staging files into compressed archives serves multiple adversary objectives: reducing file size for faster transfer, evading DLP controls that may not inspect compressed content, and consolidating multiple files into a single exfiltration package. The PowerShell initiation indicates the attacker used scripting to automate the compression process, likely part of the PayrollSupportTool.ps1 payload executed earlier. This marks a critical escalation from reconnaissance and discovery to active data theft preparation.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-10T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessUniqueId
```

### 🖼️ Screenshot
<img width="791" height="213" alt="image" src="https://github.com/user-attachments/assets/d329e2e9-e0e4-4570-a7ee-1529b296caf6" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for archive file creation (.zip, .rar, .7z, .tar.gz) in non-standard locations or with suspicious naming patterns (export, stage, data, backup, temp). Correlate the InitiatingProcessUniqueId 2533274790396713 with DeviceProcessEvents to identify all actions taken by this specific PowerShell instance. Query DeviceFileEvents for files added to the archive immediately before creation to identify what sensitive data was packaged. Monitor for subsequent file transfer activity involving export_stage.zip via network connections, cloud uploads, or removable media. Use FileProfile enrichment to determine if the archive still exists and retrieve it for forensic analysis.

</details>
---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Outbound Connectivity Test</strong></summary>

### 🎯 Objective
Confirm that outbound access was tested prior to any attempted transfer.

### 📌 Finding
PowerShell-initiated network connection detected to example.com immediately following data staging activity. The connection occurred 21 seconds after the creation of export_stage.zip, confirming the attacker tested outbound connectivity before attempting exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:31.185 AM |
| InitiatingProcessFileName | powershell.exe |
| InitiatingProcessCommandLine | "powershell.exe" |
| RemoteIP | 23.215.0.136 |
| RemoteUrl | example.com |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1016 (System Network Configuration Discovery)** and pre-exfiltration testing behavior. The use of example.com as a connectivity test target is significant because it is a benign, widely-accessible domain specifically reserved for documentation and testing purposes (RFC 2606). Attackers commonly use such domains to verify outbound network access without triggering threat intelligence alerts that malicious infrastructure would generate. The 21-second gap between data staging and connectivity testing demonstrates methodical, hands-on-keyboard behavior where the attacker validated the exfiltration path before transmitting sensitive data. This pre-flight check confirms the attacker's operational security awareness and intent to exfiltrate the staged archive.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceNetworkEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where isnotempty(RemoteIPType)
| where isnotempty(RemoteUrl)
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="930" height="166" alt="image" src="https://github.com/user-attachments/assets/d5875cf2-0202-4f8f-b5a1-fe05c964cf05" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for connections to benign testing domains (example.com, example.org, httpbin.org, ifconfig.me) from non-administrative accounts or servers, especially when preceded by data staging activity. Hunt for PowerShell network connections that occur within short time windows after archive file creation. Correlate this connectivity test with subsequent connections to the same or different external IPs to identify the actual exfiltration destination. Stack count by RemoteUrl to identify unusual testing domains across the environment. Query for similar patterns where file archiving is followed by network connectivity tests within 1-5 minutes.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Registry-Based Persistence</strong></summary>

### 🎯 Objective
Identify evidence of persistence established via a user Run key.

### 📌 Finding
Registry modification detected in the HKEY_CURRENT_USER Run key on sys1-dept, establishing persistence for the malicious PayrollSupportTool.ps1 script. The registry value was set to execute the PowerShell payload with execution policy bypass on every user logon.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:59.603 AM |
| InitiatingProcessAccountName | 5y51-d3p7 |
| ActionType | RegistryValueSet |
| RegistryKey | HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| RegistryValueData | powershell.exe -ExecutionPolicy Bypass -File "C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1" |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)**. Registry Run keys are one of the most common persistence mechanisms on Windows systems, ensuring the malicious script executes automatically whenever the compromised user logs on. The attacker placed the exact command used during initial execution into the persistence mechanism, maintaining the execution policy bypass to evade PowerShell restrictions. This occurs 28 seconds after the connectivity test, indicating the attacker followed a methodical checklist: stage data, test connectivity, establish persistence, then proceed with exfiltration. The use of the user-specific SID in the registry path ensures persistence survives across sessions for this specific account.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceRegistryEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has "Run"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueData
```

### 🖼️ Screenshot
<img width="929" height="193" alt="image" src="https://github.com/user-attachments/assets/d7c56536-a0dd-4c10-b195-d6e387b227b4" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor all RegistryValueSet actions under Run and RunOnce keys in both HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE hives. Hunt for registry values containing PowerShell commands with execution policy bypasses, encoded commands, or scripts executing from user-writable directories like Downloads or Temp. Query for registry modifications occurring shortly after malicious script execution to identify persistence establishment patterns. Stack count RegistryValueData containing "powershell", "-enc", "-exec bypass", or suspicious file paths. Correlate registry persistence with subsequent logon events to identify when the persistence mechanism successfully triggered.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Persistence</strong></summary>

### 🎯 Objective
Confirm a scheduled task was created or used to automate recurring execution.

### 📌 Finding
Scheduled task creation detected on sys1-dept using schtasks.exe to establish daily execution of the malicious PayrollSupportTool.ps1 script. The task named "BonusReviewAssist" was configured to run daily with execution policy bypass, ensuring persistent access beyond the current session.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:47:40.825 AM |
| AccountName | 5y51-d3p7 |
| ProcessCommandLine | "schtasks.exe" /Create /SC DAILY /TN BonusReviewAssist /TR "powershell.exe -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1" /F |
| InitiatingProcessCommandLine | "powershell.exe" |
| Task Name | BonusReviewAssist |
| Schedule | DAILY |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task)**. The attacker established a second persistence mechanism approximately 20 minutes after the registry Run key, demonstrating defense-in-depth from an adversary perspective. Scheduled tasks provide persistence that survives user logoff, system reboots, and even if the registry Run key is discovered and removed. The task name "BonusReviewAssist" employs social engineering to appear legitimate within a corporate environment, particularly during year-end bonus cycles. The `/F` flag indicates the attacker forcefully overwrote any existing task with the same name. The daily schedule ensures the malicious script executes repeatedly, maintaining access and potentially exfiltrating updated data on an ongoing basis.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where ProcessCommandLine has "schtasks"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="937" height="315" alt="image" src="https://github.com/user-attachments/assets/a98a4c91-7d45-4ee1-8067-2fabc624c610" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for schtasks.exe executions with `/Create` parameter, especially when initiated by PowerShell or script interpreters. Hunt for scheduled tasks configured to execute PowerShell with execution policy bypasses or scripts from user-writable directories. Query Security event logs (Event ID 4698) for scheduled task creation events. Stack count task names across the environment to identify suspicious naming patterns that mimic legitimate services. Correlate scheduled task creation with registry persistence mechanisms occurring within the same timeframe to identify layered persistence strategies. Use `Get-ScheduledTask` or query the Task Scheduler service to enumerate all tasks and identify those executing from non-standard paths.

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<!-- Duplicate Flag 1 section for Flags 2–20 -->

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
