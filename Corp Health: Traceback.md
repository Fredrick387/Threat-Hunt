
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
Blend malicious activity into routine maintenance to avoid detection and establish an initial execution foothold.

### 📌 Finding
A PowerShell maintenance script appeared on only one workstation and executed during off-hours, outside normal maintenance cycles.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-25T04:15:21Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Attackers often masquerade malicious scripts as maintenance tasks to evade scrutiny. This aligns with MITRE ATT&CK **T1059.001 – Command and Scripting Interpreter: PowerShell** and represents the initial execution stage of the attack.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Baseline approved maintenance scripts across endpoints and alert on scripts that execute on a single host or outside approved maintenance windows.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Command and Control – Initial Beacon</strong></summary>

### 🎯 Objective
Test outbound connectivity and establish a command-and-control (C2) communication channel.

### 📌 Finding
The suspicious maintenance script initiated outbound network communication during off-hours.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:46:08.400686Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Early beaconing confirms attacker control and shifts the incident from “suspicious activity” to active compromise. This maps to **T1071.001 – Application Layer Protocol: Web Protocols**.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor network events where PowerShell or scripts initiate outbound connections, especially during off-hours.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Command and Control – Beacon Destination</strong></summary>

### 🎯 Objective
Reach a listening service to exchange instructions or data.

### 📌 Finding
The compromised host attempted to connect to a local listener masquerading as a benign service.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:46:08.400686Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Localhost beacons are often used to proxy traffic or stage internal C2. This aligns with **T1090 – Proxy** and **T1071 – Command and Control**.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on unexpected connections to localhost ports initiated by scripts or non-service binaries.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Command and Control – Successful Beacon</strong></summary>

### 🎯 Objective
Confirm stable communication with the C2 channel.

### 📌 Finding
A successful outbound connection occurred days after initial attempts, indicating persistent retry behavior.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-30T01:03:17.6985973Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Delayed but successful C2 connections indicate persistence and patience, consistent with **T1071 – Command and Control** and **T1021 – Remote Services (indirect control)**.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Track repeated failed connection attempts followed by a success to identify long-lived beacons.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Collection – Data Staging</strong></summary>

### 🎯 Objective
Prepare internal data for later analysis or exfiltration.

### 📌 Finding
A diagnostic CSV file was created in an unusual CorpHealth diagnostics directory.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <From logs> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Associated PowerShell command> |

### 💡 Why it matters
Staging data locally is a precursor to exfiltration. This aligns with **T1074.001 – Data Staged: Local Data Staging**.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on file creation in diagnostic or operational folders by scripts or interactive PowerShell sessions.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Collection – File Integrity Verification</strong></summary>

### 🎯 Objective
Preserve or validate collected data before further use.

### 📌 Finding
The staged diagnostic file had a recorded SHA-256 hash, indicating deliberate handling.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <From logs> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Associated PowerShell command> |

### 💡 Why it matters
Hashing indicates controlled data handling, aligning with **T1560 – Archive Collected Data** and **T1074 – Data Staging** behaviors.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Correlate file creation with hash calculation or metadata access to identify deliberate staging.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Collection – Alternate Staging Location</strong></summary>

### 🎯 Objective
Maintain redundant or working copies of staged data.

### 📌 Finding
A second inventory CSV with a different hash was created in a user Temp directory.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | <From logs> |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | <Associated PowerShell command> |

### 💡 Why it matters
Multiple staged copies suggest manual processing and preparation, consistent with **T1074.001 – Local Data Staging** and advanced attacker tradecraft.

### 🔧 KQL Query Used
<Paste KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Look for similar filenames with different hashes across multiple directories as an indicator of attacker working copies.

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
