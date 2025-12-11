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
