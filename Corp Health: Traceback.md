
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/0a9d2335-9bd4-425b-89f6-a481c075a401"
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
- **Link:** https://docs.google.com/forms/d/e/1FAIpQLSfXHDP8VZmGdKF5YCNWTKd8Sg16zLMqRC1262OV_poqomySjQ/viewform

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

<img width="948" height="303" alt="image" src="https://github.com/user-attachments/assets/27c3ea89-93be-4655-9962-bfd5ab38c330" />


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
<summary id="-flag-8">🚩 <strong>Flag 8: Credential Access – Suspicious Registry Modification</strong></summary>

### 🎯 Objective
Inspect or manipulate system-level configuration in preparation for credential access, token harvesting, or follow-on persistence.

### 📌 Finding
A PowerShell script associated with the suspicious maintenance activity created a new registry key under the system EventLog service path. This action is anomalous for standard CorpHealth maintenance behavior and occurred shortly after data staging activity, indicating intentional system inspection or tampering.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-25T04:14:40.985Z |
| Process | powershell.exe |
| Parent Process | cmd.exe |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |
| Registry Key | HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent |
| Token Elevation | TokenElevationTypeFull |
| Initiating User | ops.maintenance |

### 💡 Why it matters
Registry interaction at the **HKLM\SYSTEM** level requires elevated privileges and is rarely necessary for routine diagnostics. Modifying EventLog service paths can support **credential harvesting simulations**, log manipulation, or preparation for stealthy persistence. This activity aligns with **MITRE ATT&CK T1003 (Credential Access)** and **T1112 (Modify Registry)**, indicating the attacker is exploring how to maintain authenticated access beyond the current script execution.

### 🔧 KQL Query Used
let startTime = datetime(2025-11-23T00:00:00Z);
let endTime = datetime(2025-11-27T23:59:59Z);
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| where InitiatingProcessCommandLine contains ".ps1"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueData, RegistryValueName, RegistryValueType,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessTokenElevation, InitiatingProcessFolderPath

### 🖼️ Screenshot
<img width="1418" height="165" alt="image" src="https://github.com/user-attachments/assets/2017a335-757d-4a7e-9165-b7bb388c4e41" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
When you see suspicious data staging followed by registry activity:
- Pivot to **DeviceRegistryEvents** where the **initiating process or command line matches the original script**
- Prioritize **HKLM\SYSTEM** and **Services** paths—these imply elevated access
- Think defensively: attackers often check *“Can I come back later without re-running this script?”* before attempting noisy actions like exfiltration

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Persistence</strong></summary>

### 🎯 Objective
Establish persistence on the compromised host by creating a scheduled task that can execute attacker-controlled code under a privileged context (SYSTEM), ensuring continued access even if the original script is removed.

### 📌 Finding
A new scheduled task was created on **ch-ops-wks02** that does not align with standard CorpHealth maintenance behavior.  
The task registration occurred via the Windows Task Scheduler service, which operates as SYSTEM, indicating that the attacker leveraged delegated or borrowed SYSTEM execution rather than an interactive SYSTEM login.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-30T00:13:54.526Z |
| Registry Key | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_52D6CA |
| Initiating Account | system |
| Initiating Process | svchost.exe |
| Command Line | svchost.exe -k netsvcs -p |

### 💡 Why it matters
Scheduled tasks are a common and durable persistence mechanism (**MITRE ATT&CK: T1053.005 – Scheduled Task/Job: Scheduled Task**).  
The key insight here is that **the creator of the task does not need to be SYSTEM**. By abusing trusted management tooling or services, an attacker can cause SYSTEM to register and run the task on their behalf.  
This allows persistence that blends in with legitimate administrative activity and complicates attribution, since logs show SYSTEM as the actor rather than the original compromised user.

### 🔧 KQL Query Used
```
let startTime = datetime(2025-11-21T00:00:00Z);
let endTime = datetime(2025-12-15T23:59:59Z);
DeviceRegistryEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains "sch"
| where ActionType in ("RegistryKeyCreated","RegistryValueSet")
| project TimeGenerated, DeviceName, RegistryValueName, RegistryKey, InitiatingProcessAccountName, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="1498" height="163" alt="image" src="https://github.com/user-attachments/assets/736ee004-7b51-4180-9697-113dd744ef53" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When hunting for scheduled-task persistence, do not filter only on the suspected user account.  
Instead:
- Search **DeviceRegistryEvents** for keys under `Schedule\TaskCache\Tree`
- Correlate task creation times with earlier suspicious scripts or processes
- Remember that **SYSTEM in the logs may simply be the service executing the request**, not the original attacker  
This mindset helps uncover persistence even when attackers intentionally “hide behind” SYSTEM.

</details>
---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Registry-Based Ephemeral Persistence (Run Key)</strong></summary>

### 🎯 Objective
Establish short-lived persistence by ensuring malicious code executes on the next system startup or user logon, then remove evidence to evade detection.

### 📌 Finding
A registry value was written to the Windows Run key pointing to a PowerShell script associated with the suspicious maintenance activity. The value was intended to trigger execution once during startup or logon and was later removed, consistent with ephemeral persistence behavior.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-25T04:24:48.895Z |
| Process | powershell.exe |
| Parent Process | <Placeholder> |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Registry.ps1 |
| Registry Key | HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run |
| Registry Value Name | MaintenanceRunner |
| Initiating Account | ops.maintenance |

### 💡 Why it matters
Registry Run keys are a classic Windows persistence mechanism that execute automatically on startup or logon.  
The create-and-delete pattern observed here indicates **ephemeral persistence**, designed to survive a reboot or disruption while minimizing forensic footprint.  

This behavior maps to **MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** and is commonly used once attackers already have execution and beaconing established.

Importantly, attackers often deploy this *before* noisy actions like exfiltration to ensure re-entry if access is lost.

### 🔧 KQL Query Used
let startTime = datetime(2025-11-21T00:00:00Z);
let endTime = datetime(2025-12-15T23:59:59Z);
DeviceRegistryEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains "run"
| project TimeGenerated, DeviceName, ActionType, RegistryValueName, RegistryKey, InitiatingProcessAccountName, InitiatingProcessCommandLine

### 🖼️ Screenshot
<img width="1006" height="219" alt="image" src="https://github.com/user-attachments/assets/efb2431e-9e1f-4839-82ca-5c09ad7813cc" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating suspicious scripts or maintenance tooling, pivot from execution into **registry activity tied to the same script or command line**.  
Specifically:
- Search for RegistryValueSet events under Run keys
- Correlate timing with script execution or network beaconing
- Remember that persistence actions may be executed under SYSTEM or service accounts, not attacker usernames

Ephemeral persistence often appears subtle — look for **short-lived registry changes near suspicious activity windows**, not long-standing autoruns.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Privilege Escalation – Application-Level Capability Probe</strong></summary>

### 🎯 Objective
Assess whether the executing process has the capability to perform privileged actions by probing application-level configuration and privilege boundaries without performing a successful escalation.

### 📌 Finding
A PowerShell command executed on **ch-ops-wks02** explicitly triggered an application-level configuration adjustment event associated with a simulated privilege escalation check. The activity indicates **capability probing**, not confirmed privilege escalation.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:47:21.852Z |
| Process | powershell.exe |
| Executing User | ops.maintenance |
| ActionType | PowerShellCommand |
| Command | `$tok=$FlagMap["PrivEsc-Sim"]; Log "Config Adjust: application event"` |

### 💡 Why it matters
Privilege escalation frequently begins with **non-destructive capability testing** rather than immediate exploitation. This event represents an explicit attempt to determine whether higher-privileged actions are possible from the current execution context.

Unlike registry-based persistence or token modification, this activity occurs entirely at the **application logic level**, reinforcing that:
- Telemetry reflects **intent and probing**, not outcome
- Privilege escalation attempts may not produce durable system changes
- Early-stage probes often precede credential access, persistence, or exfiltration

This behavior aligns with **MITRE ATT&CK TA0004 (Privilege Escalation)** and reflects attacker tradecraft designed to validate access boundaries before committing to riskier actions.

### 🔧 KQL Query Used
<placeholder>

### 🖼️ Screenshot
<placeholder>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Do not rely solely on registry or process-creation telemetry to identify privilege escalation. Incorporate **application-level PowerShell telemetry** that captures:
- Capability testing
- Privilege boundary checks
- Simulated escalation logic

Early identification of probing behavior enables detection **before** escalation succeeds, persistence is established, or sensitive data is accessed.

</details>

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
