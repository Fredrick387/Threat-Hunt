
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
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

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Execution – Suspicious Maintenance Script</strong></summary>

### 🎯 Objective
Gain initial execution on the endpoint by masquerading malicious activity as legitimate system maintenance.

### 📌 Finding
A PowerShell-based maintenance script executed during off-hours on a single workstation and was not observed across peer systems.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-25T04:15:21Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Attackers frequently abuse trusted maintenance mechanisms to blend malicious execution into normal operations. A **host-unique script**, running **outside business hours**, with **PowerShell execution policy bypass**, strongly aligns with **MITRE ATT&CK T1059.001 (PowerShell)** and represents an early execution foothold that can enable follow-on actions.

### 🔧 KQL Query Used


### 🖼️ Screenshot
<img width="772" height="288" alt="image" src="https://github.com/user-attachments/assets/983d6b17-db05-4329-8a1d-22b1842a1e88" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When you find a suspicious script, treat it as your **primary pivot**:
- Search for all executions of the script across time
- Compare presence across other endpoints to establish uniqueness
- Off-hours execution + uniqueness is sufficient to justify deeper hunting, even without a formal baseline

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Command and Control – Initial Beacon Attempt</strong></summary>

### 🎯 Objective
Test outbound connectivity and signal presence to attacker-controlled infrastructure.

### 📌 Finding
The maintenance script initiated outbound network activity inconsistent with standard internal update or telemetry behavior.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:46:08.400686Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Outbound network traffic originating from a maintenance script indicates the script is **active logic**, not a passive task. This marks the transition from execution to **command-and-control behavior**, aligning with **MITRE ATT&CK T1071 (Application Layer Protocol)**.

### 🔧 KQL Query Used
```
let anchorTime = datetime(2025-11-25T04:15:21Z);
let startTime = anchorTime - 15d;
let endTime = anchorTime + 15d;
let device = "ch-ops-wks02";
DeviceNetworkEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == device
| project TimeGenerated, ActionType, InitiatingProcessFileName,
InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="781" height="116" alt="image" src="https://github.com/user-attachments/assets/bb1e1e9c-e12e-4642-a10e-98d50ae00664" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Once a suspicious script is identified:
- Pivot immediately to network events where the **initiating process or command line contains the script**
- Do not restrict time ranges too aggressively—attackers often retry over days
- At this stage, *any* outbound connection is suspicious, regardless of destination reputation

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Command and Control – Beacon Destination</strong></summary>

### 🎯 Objective
Establish a communication channel to receive instructions or deliver staged data.

### 📌 Finding
The script attempted repeated connections to a specific IP and port combination.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <Placeholder> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Identifying the beacon destination provides the first **off-host indicator of compromise**. Even loopback or internal destinations can represent proxies or staging listeners. This behavior maps to **MITRE ATT&CK T1071 (C2)** and **T1090 (Proxy)**.

### 🛠️ Detection Recommendation

**Hunting Tip:**  
After confirming outbound activity:
- Group network events by RemoteIP and RemotePort
- Look for repetition and consistency over time
- Avoid assuming all C2 must be external—early-stage infrastructure is often local or indirect

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Command and Control – Successful Beacon</strong></summary>

### 🎯 Objective
Achieve reliable two-way communication with attacker infrastructure.

### 📌 Finding
A successful outbound connection was eventually established after multiple attempts across several days.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-30T01:03:17.6985973Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
The first successful beacon represents the point where the attacker likely gained interactive control. This timestamp anchors the attack timeline and aligns with **MITRE ATT&CK T1071 (Command and Control)**.


### 🖼️ Screenshot

![Uploading image.png…]()


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Always identify:
- First attempt
- First successful connection
- Most recent successful connection  
Attackers often retry quietly over long periods—narrow time windows will cause missed detections.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Collection – Data Staging</strong></summary>

### 🎯 Objective
Prepare internal data for review, filtering, or later exfiltration while remaining low-noise.

### 📌 Finding
A structured diagnostic file was created in a CorpHealth diagnostics directory not typically used for ad-hoc exports.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <Placeholder> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Placeholder> |

### 💡 Why it matters
Local data staging is a precursor to exfiltration and allows attackers to curate exactly what they want to steal. This aligns with **MITRE ATT&CK T1074.001 (Local Data Staging)**. Exfiltration is noisy—attackers often stage and validate data first.

### 🔧 KQL Query Used
```
let device = "ch-ops-wks02";
DeviceFileEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == device
| where ActionType in ("FileCreated","FileModified","FileCopied")
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1089" height="138" alt="image" src="https://github.com/user-attachments/assets/4a80caca-d518-4d62-9481-77618a07de54" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Once C2 is confirmed:
- Pivot to **file creation events where the initiating process or command line matches the script**
- Focus on diagnostics, ProgramData, and temp directories
- Structured formats (CSV, JSON, XML) are common staging artifacts

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Collection – File Integrity Handling</strong></summary>

### 🎯 Objective
Validate, track, or preserve staged data prior to further processing.

### 📌 Finding
Hash metadata was recorded for the staged file, indicating deliberate handling rather than incidental creation.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <Placeholder> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Placeholder> |

### 💡 Why it matters
Hash awareness demonstrates attacker discipline and supports **MITRE ATT&CK T1074 (Data Staging)** and **T1560 (Prepare Data)**. This suggests the data is intended for reuse, comparison, or exfiltration.


### 🖼️ Screenshot
<img width="1093" height="210" alt="image" src="https://github.com/user-attachments/assets/973312b2-900a-4732-8169-8d85e3d75c70" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
After identifying one staged file:
- Search for other files with similar names or sizes
- Compare hashes to identify working copies or iterations
- Assume attackers rarely rely on a single artifact

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Collection – Alternate Staging Location</strong></summary>

### 🎯 Objective
Maintain a secondary or intermediate working copy of collected data.

### 📌 Finding
A second, similarly named file with a different hash was created in a user temp directory.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <Placeholder> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Placeholder> |

### 💡 Why it matters
Multiple near-identical files across directories indicate manual interaction or iterative processing, reinforcing attacker presence. This aligns with **MITRE ATT&CK T1074.001 (Local Data Staging)**.


### 🖼️ Screenshot
<img width="1093" height="196" alt="image" src="https://github.com/user-attachments/assets/ffeb05d6-4fee-40e0-bb0c-6f248b6d72d9" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When you find one staging artifact:
- Assume there are more
- Expand searches to user temp paths and alternate operational directories
- Let naming patterns guide additional pivots, not just exact matches

</details>


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
