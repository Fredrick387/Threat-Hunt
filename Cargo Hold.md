Markdown# New Threat Hunt Report - Cargo Hold
*Lab Environment: [e.g., Cyber Range VM] | Date: [Current Date] | Tools: [e.g., KQL in Log Analytics]*

<img width="1280" height="720" alt="image" src="https://github.com/user-attachments/assets/e3f3299b-68f1-4402-a994-2856a61803cc" />


# 🚩 INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社

**📋 INCIDENT BRIEF**

**SITUATION**  
After establishing initial access on **November 19th**, network monitoring detected the attacker returning approximately **72 hours later**. Suspicious lateral movement and large data transfers were observed overnight on the file server.

**COMPROMISED SYSTEMS**  
[REDACTED - Investigation Required]

**EVIDENCE AVAILABLE**  
Microsoft Defender for Endpoint logs

**Query Starting Point**
```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
```

## Hunt Overview
[Brief description of the scenario, objective, and key findings. Keep it 2-3 sentences for quick read.]

| Flag | Technique | MITRE ID | Priority |
|------|-----------|----------|----------|
| 1    | [Technique] | [ID] | Critical |
| 2    | [Technique] | [ID] | High |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
---

### 🚩 Flag 1: INITIAL ACCESS - Return Connection Source
**🎯 Objective**  
After establishing initial access, sophisticated attackers often wait hours or days (dwell time) before continuing operations. They may rotate infrastructure between sessions to avoid detection.

**📌 Finding**  
159.26.106.98

**🔍 Evidence**

| Field            | Value                            |
|------------------|----------------------------------|
| Device Name      | azuki-sl                         |
| Timestamp        | Nov 22, 2025 7:27:53 AM          |
| Action Type      | LogonSuccess                     |


**💡 Why it matters**  
The IP address discovered is the new source the attacker used when returning approximately 72 hours after the initial compromise.
Sophisticated adversaries commonly rotate infrastructure between sessions to avoid linking new activity to the original breach and to evade detection based on known-bad IPs.
Identifying this different return IP confirms the attacker has maintained access, exercised patience (dwell time), and is now escalating the intrusion (MITRE ATT&CK TA0001 – Initial Access sustained via T1078 – Valid Accounts).

**🔧 KQL Query Used**
```
DeviceLogonEvents
| where DeviceName contains "azuki" 
| where Timestamp between (startofday(datetime(2025-11-22)) .. endofday(datetime(2025-11-24)))
| where isnotempty(RemoteIP)
| where ActionType contains "success"
| project Timestamp, DeviceId, DeviceName, ActionType, InitiatingProcessRemoteSessionIP, RemoteIP
```
**🖼️ Screenshot**
<img width="1704" height="668" alt="image" src="https://github.com/user-attachments/assets/ec26dcb6-667d-4b6c-a444-e7159bc1c784" />

**🛠️ A.I. Detection Recommendation**
```
DeviceLogonEvents
| where TimeGenerated > ago(30d)                          // Adjust window as needed (e.g., last 30 days)
| where isnotempty(RemoteIP)                              // Only remote logons with a real IP
| where LogonType in ("RemoteInteractive", "Network")     // Focus on RDP and network logons (common for attackers)
| where AccountName !contains "$"                         // Exclude machine accounts (optional – reduces noise)
| summarize LogonCount = count(), FirstLogon = min(TimeGenerated), LastLogon = max(TimeGenerated) by DeviceName, AccountName, RemoteIP
| where LogonCount >= 1                                    // Or raise threshold if needed
| order by LastLogon desc
```

<br>
<hr>
<br>


### 🚩 Flag 2: LATERAL MOVEMENT - Compromised Device
**🎯 Objective**  
Lateral movement targets are selected based on their access to sensitive data or network privileges. File servers are high-value targets containing business-critical information.

**📌 Finding**  
azuki-fileserver01

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-sl                          |
| Timestamp        | Nov 22, 2025 7:38:47 AM              |
| Process          | Microsoft Remote Desktop Connection                  |
| Parent Process   | powershell.exe                    |
| Command Line     | `"mstsc.exe" /V:10.1.0.188 `                 |

**💡 Why it matters**  
The command "mstsc.exe" /v:10.1.0.188 shows someone launching Remote Desktop to connect to the machine at IP 10.1.0.188.
In a compromised environment, this is a clear sign the attacker is using stolen credentials to move laterally — jumping from the machine they already control to a new target inside the network via RDP.
Finding this event reveals the attacker’s next target and confirms active hands-on-keyboard movement, a critical escalation step in most real-world breaches (MITRE ATT&CK T1021.001 – Remote Desktop Protocol).

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki-sl"
| where ProcessCommandLine contains "mstsc.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
**🖼️ Screenshot**

<img width="1710" height="305" alt="image" src="https://github.com/user-attachments/assets/60033488-393f-4f7d-9964-cd614eade49b" />
<br>
<img width="577" height="790" alt="image" src="https://github.com/user-attachments/assets/6f315126-7c0f-4824-81ad-4a4d062e8dd8" />


**🛠️ A.I. Detection Recommendation**
```
DeviceProcessEvents
| where TimeGenerated > ago(30d)                          // Adjust time window as needed
| where FileName == "mstsc.exe"                           // Focus on Remote Desktop client launches
| where ProcessCommandLine contains "/v:"                // Look for the /v switch specifying a target
| extend Target = extract(@"/v:([^ ]+)", 1, ProcessCommandLine)  // Extract the target IP/hostname
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, Target, InitiatingProcessCommandLine
| order by TimeGenerated desc
```


<br>
<hr>
<br>

### 🚩 Flag 3: LATERAL MOVEMENT - Compromised Account
**🎯 Objective**  
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts.

**📌 Finding**  
fileadmin

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-fileserver01                         |
| Timestamp        | Nov 22, 2025 7:38:49 AM                    |
| Action Type      | Logon Success                              |
| Remote IP        | 10.1.0.204                                 |


**💡 Why it matters**  
Finding the exact compromised account is essential because it shows the full scope of what the attacker can reach — in this case, sensitive files and shares that a file-server admin would normally access.
Knowing the compromised account enables immediate containment (disable/reset the account) and guides the rest of the investigation and remediation (MITRE ATT&CK T1078 – Valid Accounts used for lateral movement and data access).

**🔧 KQL Query Used**
```
DeviceLogonEvents
| where RemoteDeviceName contains "azuki" 
| where Timestamp between (startofday(datetime(2025-11-22)) .. endofday(datetime(2025-11-22)))
| project Timestamp, DeviceId, DeviceName, ActionType, InitiatingProcessRemoteSessionIP, RemoteIP
```
**🖼️ Screenshot**
[Your screenshot here]
<img width="1743" height="221" alt="image" src="https://github.com/user-attachments/assets/0ad57116-8296-4a9d-9c87-e749acd0d84d" />

<br>

<img width="642" height="166" alt="image" src="https://github.com/user-attachments/assets/4021b519-fabe-4754-b5d6-af94ada9120b" />


**🛠️ Detection Recommendation**
```
DeviceLogonEvents
| where TimeGenerated > ago(30d)                          // Adjust time window as needed
| where isnotempty(RemoteIP)                              // Only remote logons
| where LogonType in ("RemoteInteractive", "Network")     // RDP or network logons (common for lateral movement)
| where AccountName !contains "$"                         // Exclude machine accounts (optional noise reduction)
| summarize LogonCount = count(), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated), 
            Devices = make_set(DeviceName) by AccountName, RemoteIP
| where LogonCount >= 2                                   // Find accounts with multiple logons from the same remote IP
| order by LogonCount desc
```

<br>
<hr>
<br>

### 🚩 Flag 4: DISCOVERY - Share Enumeration Command
**🎯 Objective**  
Network share enumeration reveals available data repositories and helps attackers identify targets for collection and exfiltration.

**📌 Finding**  
"net.exe" share

**🔍 Evidence**

| Field            | Value                                     |
|------------------|-------------------------------------------|
| Host             | azuki-fileserver01                        |
| Timestamp        | Nov 22, 2025 7:40:54 AM                   |
| Process          |      net.exe                              |
| Parent Process   | powershell.exe                            |
| Command Line     | `"net.exe" share   `                      |

**💡 Why it matters**  
The attacker ran a command to list all visible network shares from the compromised machine.
This simple action instantly shows them which servers and workstations are sharing folders — and, more importantly, which ones their current stolen account can actually reach.
Finding accessible shares is a critical step for attackers because those folders often contain the most valuable data (finance, HR, backups, databases) and become the primary targets for collection and exfiltration (MITRE ATT&CK T1135 – Network Share Discovery). Spotting this early tells us the attacker is actively mapping the network for high-value data locations.

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "net"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
```
**🖼️ Screenshot**
<img width="1785" height="727" alt="image" src="https://github.com/user-attachments/assets/1c0c90ca-33bb-4034-81d2-4c21ab424e2c" />


**🛠️ Detection Recommendation**
```
DeviceProcessEvents
| where TimeGenerated > ago(30d)                          // Adjust time window as needed
| where FileName in ("net.exe", "powershell.exe", "cmd.exe")  // Common processes used for share discovery
| where ProcessCommandLine has_any("net view", "net share", "Get-SmbShare", "win32_share", "wmic share")
| extend Target = extract(@"\\\\([^\\]+)", 1, ProcessCommandLine)  // Extracts potential target hostname if present
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName, Target, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<br>
<hr>
<br>

### 🚩 Flag #5: DISCOVERY - Remote Share Enumeration
**🎯 Objective**  
Attackers enumerate remote network shares to identify accessible file servers and data repositories across the network.

**📌 Finding**  
"net.exe" view \\10.1.0.188

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-fileserver01                         |
| Timestamp        | Nov 22, 2025 7:42:01 AM                    |
| Process          | net.exe                                    |
| Parent Process   | powershell.exe                             |
| Command Line     | `net.exe" view \\10.1.0.188`               |

**💡 Why it matters**  
The attacker ran a command to list network shares on a remote machine (not just the local one), revealing which folders and files on other servers they can actually access with their current stolen credentials.
This step is crucial because it helps the attacker quickly locate high-value data repositories — such as file servers holding finance, HR, or customer files — that are often the ultimate target for exfiltration or encryption.
Detecting remote share enumeration early signals that the attacker has moved beyond basic recon and is actively hunting for data across the network (MITRE ATT&CK T1135 – Network Share Discovery).

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "\\"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by Timestamp asc
```
**🖼️ Screenshot**
<img width="1665" height="597" alt="image" src="https://github.com/user-attachments/assets/929005b2-7623-404a-861c-f511c4537d9b" />


**🛠️ Detection Recommendation**
```
DeviceProcessEvents
| where TimeGenerated > ago(30d)                          // Adjust time window as needed
| where FileName in ("net.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any("net view \\\\", "net use \\\\", "Get-SmbMapping", "Invoke-Command -ComputerName")
| extend RemoteTarget = extract(@"\\\\([^\\ ]+)", 1, ProcessCommandLine)  // Extracts the remote hostname/server queried
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, RemoteTarget, InitiatingProcessCommandLine
| order by TimeGenerated desc
```



<br>
<hr>
<br>


### 🚩 Flag #6: DISCOVERY - Privilege Enumeration
**🎯 Objective**  
Understanding current user privileges and group memberships helps attackers determine what actions they can perform and whether privilege escalation is needed.

**📌 Finding**  
"whoami.exe" /all

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-fileserver01                         |
| Timestamp        | 2025-11-22T00:42:24.1217046Z               |
| Process          | whoami.exe                     |
| Parent Process   | "powershell.exe                      |
| Command Line     | `"whoami.exe" /all`                 |

**💡 Why it matters**  
Running whoami.exe /all is a high-signal discovery action that reveals the attacker’s effective privileges, group memberships, token elevation status, and assigned rights under the current session. This information allows an attacker to immediately assess whether they already have administrative or delegated access, or whether privilege escalation is required before proceeding. 

In real-world intrusions, this step often precedes credential abuse, lateral movement, or direct access to sensitive systems when elevated roles (e.g., Domain Users with special rights, local administrators, backup operators) are discovered. 

The use of this command via PowerShell strongly aligns with MITRE ATT&CK T1033 – System Owner/User Discovery and T1069 – Permission Group Discovery. Because it provides rapid confirmation of attack feasibility with minimal noise, whoami /all is commonly observed in hands-on-keyboard activity and is a reliable indicator of interactive attacker presence, not automated background activity.

**🔧 KQL Query Used** (filter "whoami")
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by Timestamp asc
```
**🖼️ Screenshot**
<img width="1505" height="629" alt="image" src="https://github.com/user-attachments/assets/65486d2d-e43f-4ff1-b2f0-1070a4263538" />


**🛠️ Detection Recommendation**
<br>
***Hunting tip:***
Prioritize results where the initiating process is powershell.exe, the account is non-IT or service-based, or the activity occurs shortly after initial access or lateral movement events.
<br>
```
DeviceProcessEvents
| where TimeGenerated > ago(30d)   // Tune for hunt scope
| where FileName in ("whoami.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any(
    "whoami /all",
    "whoami /groups",
    "whoami /priv",
    "Get-LocalGroup",
    "Get-LocalGroupMember",
    "net localgroup",
    "net user"
)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by TimeGenerated desc
```


<br>
<hr>
<br>

### 🚩 Flag #7: DISCOVERY - Network Configuration Command
**🎯 Objective**  
Network configuration enumeration helps attackers understand the target environment, identify domain membership, and discover additional network segments.

**📌 Finding**  
"ipconfig.exe" /all

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-fileserver01                         |
| Timestamp        | 2025-11-22T00:42:46.3655894Z               |
| Process          | ipconfig.exe                     |
| Parent Process   | "powershell.exe"                       |
| Command Line     | `"ipconfig.exe" /all`                 |

**💡 Why it matters**  
Running ipconfig /all provides attackers with detailed insight into the host’s network configuration, including IP addresses, DNS servers, default gateways, and domain membership. This information helps determine whether the system is domain-joined, identify internal DNS infrastructure, and reveal additional network segments that may be reachable. 

In real-world intrusions, this command is commonly executed immediately after initial access to orient the attacker within the environment. When observed alongside other discovery activity, it strongly indicates hands-on-keyboard reconnaissance rather than benign automation. 

This behavior maps to MITRE ATT&CK T1016 – System Network Configuration Discovery and is a reliable early-stage signal of active adversary presence.

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by Timestamp asc
```
**🖼️ Screenshot**
<img width="1499" height="630" alt="image" src="https://github.com/user-attachments/assets/e68c218e-8f6c-4291-b1f8-1109e75b5e36" />

**🛠️ Detection Recommendation**
<br>
***Hunting Tip***

Prioritize results where network enumeration commands are executed shortly after process launch from powershell.exe or cmd.exe, especially on servers or non-workstation hosts. Chaining this activity with subsequent share discovery or credential access events often reveals a clear attacker reconnaissance sequence.
<br>
```
DeviceProcessEvents
| where TimeGenerated > ago(30d) 
| where FileName in ("ipconfig.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any("ipconfig /all", "ipconfig.exe /all", "Get-NetIPConfiguration", "Get-NetAdapter")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc

```


<br>
<hr>
<br>

### 🚩 Flag #8: DEFENSE EVASION - Directory Hiding Command
**🎯 Objective**  
Modifying file system attributes to hide directories prevents casual discovery by users and some security tools. Document the exact command line used.

**📌 Finding**  
"attrib.exe" +h +s C:\Windows\Logs\CBS

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-fileserver01                         |
| Timestamp        | 2025-11-22T00:55:43.9986049Z              |
| Process          | attrib.exe                  |
| Parent Process   | powershell.exe                       |
| Command Line     | `attrib.exe" +h +s C:\Windows\Logs\CBS`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-22)) .. endofday(date(2025-11-22)))
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("{", "[", "+", "|") 
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by Timestamp asc
```
**🖼️ Screenshot**
<img width="1528" height="745" alt="image" src="https://github.com/user-attachments/assets/ffed7bd7-b192-41fc-b10a-8a75131315bf" />


**🛠️ Detection Recommendation**

**Hunting Tip:**  
[Your Tip here]

```
[Your exact KQL query here]
```



<br>
<hr>
<br>


### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**

**Hunting Tip:**  
[Your Tip here]

```
[Your exact KQL query here]
```



<br>
<hr>
<br>


### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**

**Hunting Tip:**  
[Your Tip here]

```
[Your exact KQL query here]
```


<br>
<hr>
<br>

### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**

**Hunting Tip:**  
[Your Tip here]

```
[Your exact KQL query here]
```


<br>
<hr>
<br>



### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**

**Hunting Tip:**  
[Your Tip here]

```
[Your exact KQL query here]
```

