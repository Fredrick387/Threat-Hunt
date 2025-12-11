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
<img width="577" height="790" alt="image" src="https://github.com/user-attachments/assets/6f315126-7c0f-4824-81ad-4a4d062e8dd8" />
<img width="1710" height="305" alt="image" src="https://github.com/user-attachments/assets/60033488-393f-4f7d-9964-cd614eade49b" />

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
```
[Your exact KQL query here]
```
