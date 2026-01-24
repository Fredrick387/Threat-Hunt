
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
```
let startTime = datetime(2025-11-23);
let endTime = datetime(2025-12-05);
let suspectmachine = "ch-ops-wks02";
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == suspectmachine 
| where ProcessCommandLine contains "powershell" and ProcessCommandLine contains "staging"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1176" height="138" alt="image" src="https://github.com/user-attachments/assets/f8c3d399-5c44-4714-86b2-1f347bce9568" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Do not rely solely on registry or process-creation telemetry to identify privilege escalation. Incorporate **application-level PowerShell telemetry** that captures:
- Capability testing
- Privilege boundary checks
- Simulated escalation logic

Early identification of probing behavior enables detection **before** escalation succeeds, persistence is established, or sensitive data is accessed.

</details>

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: DEFENSE EVASION – Antivirus Exclusion Attempt</strong></summary>

### 🎯 Objective
The attacker attempted to weaken endpoint defenses by excluding a specific directory from Windows Defender scanning, allowing staged tools or payloads to operate without detection.

### 📌 Finding
A command was executed to add a Windows Defender exclusion for a non-standard operational directory tied to the suspicious maintenance activity. The exclusion attempt was issued via PowerShell, invoked indirectly through `cmd.exe`, consistent with evasion and obfuscation tactics.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:46:37.923Z |
| Process | cmd.exe |
| Parent Process | powershell.exe |
| Command Line | `"cmd.exe" /c echo powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force"` |

### 💡 Why it matters
Disabling or bypassing antivirus scanning is a classic **Defense Evasion** tactic. By attempting to exclude the `C:\ProgramData\Corp\Ops\staging` directory, the attacker was preparing a safe workspace for tools, staged data, or follow-on payloads without interference from endpoint protection.

This aligns with **MITRE ATT&CK T1562.001 – Impair Defenses: Disable or Modify Tools**, and typically occurs shortly before higher-risk actions such as credential access, lateral movement, or data exfiltration. Exfiltration is noisy; weakening defenses first reduces the chance of early detection.

### 🔧 KQL Query Used
<Placeholder – DeviceProcessEvents query filtering for Add-MpPreference or ExclusionPath activity>

### 🖼️ Screenshot
<Placeholder – Defender exclusion attempt via cmd.exe / PowerShell>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating suspicious scripts, always pivot into **DeviceProcessEvents** and search for security-control modifications (e.g., `Add-MpPreference`, `Set-MpPreference`). Filter by processes spawned from the suspicious script or its parent. Attackers often wrap these commands in `cmd.exe` or logging statements to test what executes versus what is blocked. Antivirus exclusion attempts frequently precede staging or execution of additional payloads.

</details>

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Execution – PowerShell Encoded Command</strong></summary>

### 🎯 Objective
Execute PowerShell commands in an obfuscated manner to evade casual inspection and signature-based detection while continuing attacker-controlled logic on the host.

### 📌 Finding
A PowerShell process executed using the `-EncodedCommand` flag under the `ops.maintenance` account. The encoded payload was Base64-encoded Unicode and required manual decoding to reveal the true command executed.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:46:25.514Z |
| Process | powershell.exe |
| Parent Process | MaintenanceRunner_Distributed.ps1 |
| Command Line | powershell.exe -NoProfile -EncodedCommand \<Base64\> |
| Decoded Command | Write-Output 'token-6D5E4EE08227' |

### 💡 Why it matters
Encoded PowerShell commands are a common defense-evasion technique used to obscure attacker intent and bypass simple logging or alerting rules. While the decoded command itself appears benign, its execution confirms that the attacker-controlled script successfully executed arbitrary PowerShell payloads. This maps to **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)** and signals readiness for higher-risk actions such as credential access, privilege manipulation, or payload staging.

### 🔧 KQL Query Used
```
let startTime = datetime(2025-11-23);
let endTime = datetime(2025-12-05);
let suspectmachine = "ch-ops-wks02";
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == suspectmachine 
| where ProcessCommandLine contains "powershell" and ProcessCommandLine contains "-EncodedCommand"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="1176" height="138" alt="image" src="https://github.com/user-attachments/assets/43a95d8e-7b34-4120-be23-78e4238aef9e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating suspicious scripts, always check for PowerShell executions using `-EncodedCommand`. Use KQL to surface candidate events, but decode Base64 payloads locally when necessary—PowerShell EncodedCommand uses Unicode, which KQL does not reliably decode. Encoded execution often precedes credential access or privilege manipulation because it allows attackers to test capabilities quietly before noisier actions like exfiltration.

</details>

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Privilege Escalation – Token Manipulation</strong></summary>

### 🎯 Objective
Adjust process token privileges to elevate execution context or blend malicious activity with higher-privilege processes.

### 📌 Finding
Windows recorded a `ProcessPrimaryTokenModified` event originating from a PowerShell process tied directly to the suspicious maintenance script. This indicates the attacker attempted to modify the primary access token of a running process — a common privilege escalation and evasion technique.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-25T04:14:07.058Z |
| ActionType | ProcessPrimaryTokenModified |
| InitiatingProcessId | 4888 |
| Process | powershell.exe |
| Account | ops.maintenance |
| Command Line | powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1 |

### 💡 Why it matters
Primary token modification is a high-signal indicator of attempted privilege escalation or token abuse. Even if full elevation does not occur, this behavior confirms the attacker was probing execution boundaries and permissions. This aligns with **MITRE ATT&CK T1134 (Access Token Manipulation)** and often precedes lateral movement, credential reuse, or persistence mechanisms. Token manipulation is quieter than spawning new SYSTEM processes and is commonly used to evade behavioral detections.

### 🔧 KQL Query Used
```
let startTime = datetime(2025-11-15);
let endTime   = datetime(2025-12-15);
DeviceEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ProcessPrimaryTokenModified"
| where InitiatingProcessCommandLine contains ".ps1"
| project TimeGenerated, ActionType, InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```


### 🖼️ Screenshot
<img width="1530" height="172" alt="image" src="https://github.com/user-attachments/assets/7f450866-2a4a-4aa0-bcb7-d262ae1a8259" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When a suspicious script is already confirmed, pivot immediately to `DeviceEvents` for `ProcessPrimaryTokenModified` actions tied to the same script or account. Token manipulation frequently occurs before louder actions such as credential dumping or network-based lateral movement, since attackers want stable execution privileges before expanding access.

</details>

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Privilege Escalation – Token Owner Identified</strong></summary>

### 🎯 Objective
Identify which security principal’s access token was modified to determine the attacker’s effective privilege level and risk impact.

### 📌 Finding
Analysis of the `ProcessPrimaryTokenModified` event reveals that the modified token belonged to a specific user SID rather than a SYSTEM or built-in administrator account. The attacker adjusted privileges on an existing user token, confirming a controlled and stealth-oriented escalation attempt rather than a noisy SYSTEM takeover.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| ActionType | ProcessPrimaryTokenModified |
| TokenChangeDescription | Privileges were added to the token |
| OriginalTokenUserSid | S-1-5-21-1605642021-30596605-784192815-1000 |
| CurrentTokenUserSid | S-1-5-21-1605642021-30596605-784192815-1000 |
| Account Context | ops.maintenance |

### 💡 Why it matters
Identifying the token owner clarifies the attacker’s intent and constraints. Modifying a **user-level token** rather than SYSTEM suggests the attacker was testing privilege boundaries or enabling specific rights (e.g., SeDebugPrivilege) without fully elevating. This aligns with **MITRE ATT&CK T1134 (Access Token Manipulation)** and often precedes credential access, lateral movement, or defense evasion. Token-level privilege adjustments are quieter than spawning elevated processes and are commonly used to blend into legitimate user activity.

### 🖼️ Screenshot
<img width="1213" height="402" alt="image" src="https://github.com/user-attachments/assets/d605ff1e-2193-4da6-92bd-6c0d6ddea8c1" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
After identifying a token modification event, always extract `OriginalTokenUserSid` and `CurrentTokenUserSid`. If they match a standard user SID rather than SYSTEM, treat this as **preparatory escalation** — attackers often tune privileges before attempting credential access or lateral movement because token manipulation is significantly less noisy than spawning elevated shells.

</details>

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Startup Folder Persistence</strong></summary>

### 🎯 Objective
Establish persistence by ensuring the malicious executable automatically launches on user logon.

### 📌 Finding
After executing the staged unsigned binary, the attacker copied the executable into a Windows Startup directory. Files placed in this location are executed automatically when a user logs in, providing a simple and reliable persistence mechanism without requiring registry modification or scheduled tasks.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp (UTC) | 2025-12-02T12:28:26.871Z |
| File Name | revshell.exe |
| File Path | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe |
| Action Type | FileRenamed |
| File Type | PortableExecutable |
| Initiating Process | dllhost.exe |
| Initiating Account | chadmin |
| Integrity Level | High |

### 💡 Why it matters
Startup folder persistence is a low-friction, high-reliability technique commonly used after initial compromise to maintain access across reboots or user logons.

From an attack-chain perspective, this confirms:
- The attacker transitioned from exploration and staging to long-term foothold establishment.
- Persistence was chosen in **user context**, aligning with earlier token manipulation rather than full SYSTEM takeover.
- The attacker favored filesystem-based persistence over noisier registry or service-based mechanisms.

**MITRE ATT&CK Mapping:**
- **TA0003 – Persistence**
- **T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**

### 🔧 KQL Query Used
```
let startTime = (todatetime('2025-11-25T04:14:07.0587586Z'));
let endTime   = datetime(2025-12-15);
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
```

### 🖼️ Screenshot
<img width="1422" height="396" alt="image" src="https://github.com/user-attachments/assets/46e5c624-6eae-4518-a8f6-8d267b70ddd9" />


### 🛠️ Detection Recommendation

**Hunting Tips:**
- Monitor `DeviceFileEvents` for `.exe` files written to:
  - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`
  - User-level Startup folders under `AppData`
- Correlate persistence placement with:
  - Recent unsigned binary execution
  - Prior outbound network activity from the same executable
- Treat Startup-folder persistence immediately following tool execution as **post-compromise confirmation**, not an initial-access signal.

</details>

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: External Tool Download via Dynamic Tunnel</strong></summary>

### 🎯 Objective
Transfer attacker tooling onto the compromised host using an external, temporary infrastructure while minimizing detection and attribution.

### 📌 Finding
Following earlier privilege manipulation and staging activity, the attacker used `curl.exe` to retrieve an unsigned executable from an external dynamic tunneling service. The file was written directly to disk under the user context, confirming deliberate ingress of follow-on tooling rather than benign update activity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp (UTC) | 2025-12-02T12:17:07.718Z |
| File Name | revshell.exe |
| Action Type | FileCreated |
| Initiating Process | curl.exe |
| Initiating Account | chadmin |
| Download URL | https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe |

### 💡 Why it matters
Dynamic tunneling services (such as ngrok) are frequently abused by attackers to host short-lived payloads that evade traditional reputation-based blocking. The use of `curl.exe` — uncommon for interactive users in many enterprise environments — further strengthens the case for malicious intent.

This activity demonstrates:
- A clear transition from **local host manipulation** to **external tool ingress**
- Use of **temporary attacker-controlled infrastructure** to reduce traceability
- Intent to execute custom tooling rather than rely solely on native utilities

**MITRE ATT&CK Mapping:**
- **TA0011 – Command and Control**
- **T1105 – Ingress Tool Transfer**

### 🔧 KQL Query Used
```
let startTime = (todatetime('2025-11-25T04:14:07.0587586Z'));
let endTime   = datetime(2025-12-15);
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

### 🖼️ Screenshot
<img width="925" height="161" alt="image" src="https://github.com/user-attachments/assets/ffc84ca0-3ab3-4653-b598-235bb5b3b60b" />


### 🛠️ Detection Recommendation

**Hunting Tips:**
- Monitor for `curl.exe`, `wget`, or `Invoke-WebRequest` initiating file writes on endpoints where they are not standard tools.
- Flag downloads from:
  - Dynamic DNS domains
  - Tunneling platforms (ngrok, cloudflared, localtunnel)
- Correlate external downloads occurring shortly after:
  - Privilege escalation attempts
  - Token modification events
  - Defender exclusion attempts

This combination strongly indicates post-exploitation tooling deployment rather than legitimate administration.

</details>

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Execution of Staged Unsigned Binary</strong></summary>

### 🎯 Objective
Transition from staging to active tool execution by launching a newly downloaded, unsigned binary under user context to establish interactive control.

### 📌 Finding
Shortly after `revshell.exe` was downloaded from an external dynamic tunnel, Defender recorded its execution on CH-OPS-WKS02. The binary was launched via `Explorer.EXE`, mimicking normal user-driven execution rather than automated service behavior.

This marks the attacker’s shift from preparation to **active post-exploitation**.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp (UTC) | 2025-12-02T12:30:03.909Z |
| Executed File | revshell.exe |
| Action Type | ProcessCreated |
| Parent Process | Explorer.EXE |
| Initiating Account | chadmin |

### 💡 Why it matters
Launching attacker tooling through `Explorer.EXE` is a common tradecraft technique to blend malicious execution into normal user activity. This avoids some behavioral detections that trigger on service-based or scripted execution.

At this stage:
- The attacker has **privileges**
- Tooling is **on disk**
- Execution confirms **interactive control intent**
- Network callbacks are likely imminent

**MITRE ATT&CK Mapping:**
- **TA0002 – Execution**
- **T1204.002 – User Execution: Malicious File**
- **TA0011 – Command and Control (follow-on)**

### 🔧 KQL Query Used
<Placeholder – DeviceProcessEvents filtered by FileName == "revshell.exe">

### 🖼️ Screenshot
<Placeholder – ProcessCreated event showing Explorer.EXE launching revshell.exe>

### 🛠️ Detection Recommendation

**Hunting Tips:**
- Alert on unsigned executables launched by `Explorer.EXE` from:
  - User profile directories
  - ProgramData paths
  - Startup folders
- Correlate execution events occurring shortly after:
  - External downloads
  - Defender exclusion attempts
  - Privilege or token modifications
- Treat “Explorer → unknown EXE” as high-risk when preceded by curl or PowerShell ingress activity

This execution event confirms the attacker has moved beyond simulation and into hands-on tooling deployment.

</details>

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: External Command-and-Control Connection Attempt</strong></summary>

### 🎯 Objective
Establish outbound command-and-control (C2) communication from the newly executed attacker tooling to an external endpoint, enabling remote interaction and tasking.

### 📌 Finding
After `revshell.exe` was executed on CH-OPS-WKS02, the binary attempted to initiate outbound network communication to an external IP address over a high, non-standard port. Defender logged multiple connection attempts originating directly from the malicious executable, confirming active C2 behavior rather than passive staging.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp (UTC) | 2025-12-02T12:57:50.950Z |
| Initiating Process | revshell.exe |
| Initiating Account | chadmin |
| Remote IP | 13.228.171.119 |
| Remote Port | 11746 |

### 💡 Why it matters
This event confirms the attacker successfully transitioned from local execution to **external command-and-control activity**. High-numbered, uncommon ports combined with unsigned binaries are strong indicators of reverse shells or custom implants.

At this stage of the intrusion:
- Privilege escalation has already occurred
- Tooling is actively running
- The attacker is attempting live remote access

**MITRE ATT&CK Mapping:**
- **TA0011 – Command and Control**
- **T1071 – Application Layer Protocol**
- **T1571 – Non-Standard Port**
- **TA0008 – Lateral Movement (potential next phase)**

### 🔧 KQL Query Used
```
let startTime = todatetime('2025-12-02T12:30:03.9096976Z');
let endTime   = datetime(2025-12-15);
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| where InitiatingProcessCommandLine contains "rev"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```

### 🖼️ Screenshot
<img width="1116" height="229" alt="image" src="https://github.com/user-attachments/assets/db70f2e6-4006-4f01-b4a9-addff54ec4fe" />


### 🛠️ Detection Recommendation

**Hunting Tips:**
- Alert on outbound connections from:
  - Unsigned executables
  - Recently created files
  - Files executed from user or ProgramData directories
- Flag high, uncommon destination ports combined with:
  - Curl-based ingress
  - Explorer-launched binaries
  - Prior Defender exclusion attempts
- Correlate process execution → network activity within minutes as a strong C2 signal

This flag represents a clear pivot from execution into active attacker control of the host.

</details>

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Persistence via Startup Folder Placement</strong></summary>

### 🎯 Objective
Establish persistence by ensuring the attacker’s executable automatically runs on user logon, allowing continued access without re-exploitation.

### 📌 Finding
After execution and failed outbound connection attempts, the attacker copied the malicious binary `revshell.exe` into a Windows Startup directory. Any executable placed in this folder is launched automatically when a user logs in, providing a simple and reliable persistence mechanism.

The file write was performed shortly after execution, indicating deliberate follow-on persistence rather than incidental file movement.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp (UTC) | 2025-12-02T12:28:26.871Z |
| File Name | revshell.exe |
| Folder Path | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ |
| Initiating Process | dllhost.exe |
| Initiating Command Line | DllHost.exe /Processid:{3AD05575-8857-4850-9277-11B85DB8E09} |

### 💡 Why it matters
Startup-folder persistence is a **low-effort, high-reliability** technique frequently used after an attacker achieves execution and outbound communication. It requires no registry modification and often evades basic persistence monitoring focused solely on Run keys or scheduled tasks.

At this point in the attack chain:
- Privilege escalation has already occurred
- External C2 communication was attempted
- Persistence ensures access survives reboot or logoff

**MITRE ATT&CK Mapping:**
- **TA0003 – Persistence**
- **T1547.001 – Boot or Logon Autostart Execution: Startup Folder**

### 🔧 KQL Query Used
```
let startTime = todatetime('2025-11-15');
let endTime   = datetime(2025-12-15);
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| where FolderPath contains "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```


### 🖼️ Screenshot
<img width="1209" height="199" alt="image" src="https://github.com/user-attachments/assets/da9dd3cd-633a-4a55-8510-046c2d243a5a" />


### 🛠️ Detection Recommendation

**Hunting Tips:**
- Monitor file creation and rename events under:
  - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
  - User Startup folders
- Correlate persistence creation shortly after:
  - Unsigned binary execution
  - External network activity
- Alert when uncommon binaries (non-installers) appear in Startup paths
- Treat persistence following failed C2 attempts as a strong indicator of attacker intent

This flag confirms the attacker transitioned from execution into **durable access** on the host.

</details>
---
<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Remote Session Source Device Identification</strong></summary>

### 🎯 Objective
Identify whether the attacker interacted with the host locally or through a remote session, and determine the unique session identifier associated with the intrusion.

### 📌 Finding
Multiple suspicious events on CH-OPS-WKS02 contained consistent remote session metadata, indicating the attacker was interacting with the system via a remote session rather than physical access. The same remote session device name appeared repeatedly across file, process, and network telemetry.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Remote Session Device Name | 对手 |
| Remote Session Present | true |
| Data Source | DeviceFileEvents / DeviceProcessEvents |
| Session Consistency | Reused across multiple attacker actions |

### 💡 Why it matters
Remote session identifiers allow defenders to correlate disparate telemetry back to a single attacker interaction point. Identifying a consistent remote session device name confirms interactive access and supports attribution of actions to a single intrusion chain rather than background automation.

MITRE ATT&CK:
- T1021 – Remote Services
- T1078 – Valid Accounts (interactive access context)


### 🖼️ Screenshot
<img width="688" height="125" alt="image" src="https://github.com/user-attachments/assets/6f464830-92ce-4aad-a223-a75d75cf6c16" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When remote session fields are populated, pivot on InitiatingProcessRemoteSessionDeviceName across all tables (Process, File, Network, Registry). Treat this value as a session label, not a hostname, and use it to bind the attacker’s activity together across the timeline.

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Remote Session Source IP Identification</strong></summary>

### 🎯 Objective
Determine the network origin used by the attacker to establish their remote interactive session with CH-OPS-WKS02.

### 📌 Finding
The same suspicious events associated with the remote session device name also contained a consistent remote session IP address. This IP appeared repeatedly across attacker-driven activity and does not belong to the internal corporate address space.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Remote Session IP | 100.64.100.6 |
| IP Type | CGNAT / Relay Address Space |
| Data Source | DeviceFileEvents / DeviceProcessEvents |
| Session Consistency | Identical across multiple events |

### 💡 Why it matters
The 100.64.0.0/10 range is commonly used for carrier-grade NAT and relay infrastructure. This strongly suggests the attacker accessed the system through an intermediate relay or tunneling service rather than directly from their true origin. This distinction is critical when reconstructing the attacker’s path and understanding why later flags require separating relay IPs from true source IPs.

MITRE ATT&CK:
- T1090 – Proxy
- T1021 – Remote Services


### 🖼️ Screenshot
<img width="688" height="125" alt="image" src="https://github.com/user-attachments/assets/f0dd4555-511f-409b-9862-22e1c21610bb" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Do not assume all non-10.x.x.x addresses represent the attacker’s true origin. Identify CGNAT or relay ranges early, then continue pivoting to locate internal pivot hosts or later public IPs that represent the attacker’s actual source.

</details>
---
<details>
<summary id="-flag-23">🚩 <strong>Flag 23: Internal Pivot Host Identified</strong></summary>

### 🎯 Objective
Identify whether the attacker leveraged an internal system as a pivot point when accessing CH-OPS-WKS02, indicating multi-hop intrusion behavior within the environment.

### 📌 Finding
Telemetry shows that the attacker’s remote session activity consistently references an internal private IP address distinct from the victim host. This internal address represents an Azure virtual network system used as an intermediary pivot before interacting with CH-OPS-WKS02.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-12-02T23:56:01.0072771Z |
| ActionType | ConnectionSuccess |
| Remote Session Device Name | 对手 |
| Internal Pivot IP | 10.168.0.6 |

### 💡 Why it matters
The presence of an internal pivot host confirms that the attacker did not access CH-OPS-WKS02 directly from an external source. Instead, they operated through another compromised internal system, increasing stealth and complicating detection.

This behavior aligns with **MITRE ATT&CK – Lateral Movement (TA0008)**, specifically techniques involving internal infrastructure hopping to reduce exposure and bypass perimeter controls. Identifying pivot hosts is critical for scoping the breach and preventing reinfection from trusted internal paths.

### 🔧 KQL Query Used
```
let startTime = todatetime(2025-11-15);
let endTime   = datetime(2025-12-15);
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| where InitiatingProcessRemoteSessionIP != "100.64.100.6"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName
```
### 🖼️ Screenshot
<img width="1216" height="197" alt="image" src="https://github.com/user-attachments/assets/24ccfc7a-de6f-4548-a285-9e6b217de391" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When analyzing remote session telemetry, always enumerate distinct `InitiatingProcessRemoteSessionIP` values. Exclude the victim’s local IP and known relay ranges (such as 100.64.0.0/10). Any remaining private 10.x.x.x address likely represents an internal pivot host that must be investigated for prior compromise.

</details>
---
<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Initial Remote Logon Detected</strong></summary>

### 🎯 Objective
Identify the earliest successful logon event indicating the attacker’s initial access to the host.

### 📌 Finding
A successful remote network logon occurred to CH-OPS-WKS02 from an external public IP using NTLM authentication. This event represents the attacker’s first confirmed foothold on the system.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:08:31.1849379Z |
| Logon Type | Network |
| Protocol | NTLM |
| Remote Device Name | 对手 |
| Remote IP | 104.164.168.17 |
| Account | chadmin |

### 💡 Why it matters
This event marks the true start of the intrusion. Network logons using NTLM from a public IP strongly suggest credential-based access rather than local activity. Identifying the first successful logon anchors the entire attack timeline and enables accurate scoping of follow-on actions.

MITRE ATT&CK:  
- TA0001 – Initial Access  
- T1078 – Valid Accounts

### 🔧 KQL Query Used
```
let startTime = todatetime(2025-11-15);
let endTime   = datetime(2025-12-15);
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (startTime .. endTime)
| where AccountName contains "chadmin"
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="897" height="317" alt="image" src="https://github.com/user-attachments/assets/7870be82-9db9-4aed-b68b-80d0e8ed0cf1" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When tracing initial access, prioritize DeviceLogonEvents with `LogonType == Network` and `RemoteIPType == Public`. Sort ascending to find the earliest foothold, then pivot forward in time using the same account and remote session metadata.

</details>
---
<details>
<summary id="-flag-25">🚩 <strong>Flag 25: External Source IP for Initial Access</strong></summary>

### 🎯 Objective
Determine the external IP address used by the attacker during their first successful logon.

### 📌 Finding
The attacker authenticated to CH-OPS-WKS02 from a public IP address not associated with internal infrastructure or known management services.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:08:31.1849379Z |
| Remote IP | 104.164.168.17 |
| IP Type | Public |
| Protocol | NTLM |

### 💡 Why it matters
Identifying the external source IP enables correlation with perimeter logs, firewall telemetry, and threat intelligence. Public IP–based authentication combined with NTLM is a common indicator of credential abuse rather than legitimate remote administration.

MITRE ATT&CK:  
- TA0001 – Initial Access  
- T1078 – Valid Accounts


### 🖼️ Screenshot
<img width="470" height="140" alt="image" src="https://github.com/user-attachments/assets/5f00e285-6d26-412a-9a4d-fd1b42b1ee30" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Always extract and preserve the first external IP used during authentication. Even if later sessions pivot internally, this IP often represents the attacker’s true origin and is critical for containment and attribution.

</details>
---
<details>
<summary id="-flag-26">🚩 <strong>Flag 26: Compromised Account Used for Initial Access</strong></summary>

### 🎯 Objective
Identify which account credentials were used by the attacker during the first successful logon.

### 📌 Finding
The attacker authenticated using the local administrative account `chadmin`, indicating either credential compromise or abuse of an overprivileged account.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Timestamp | 2025-11-23T03:08:31.1849379Z |
| Account Name | chadmin |
| Account SID | S-1-5-21-1605642021-30596605-784192815-1002 |
| Logon Type | Network |
| Protocol | NTLM |

### 💡 Why it matters
Use of an administrative account for initial access significantly increases attacker capability from the outset, reducing the need for early privilege escalation. This elevates the risk of rapid persistence, credential harvesting, and lateral movement.

MITRE ATT&CK:  
- TA0001 – Initial Access  
- T1078 – Valid Accounts  
- TA0004 – Privilege Escalation

### 🖼️ Screenshot
<img width="470" height="140" alt="image" src="https://github.com/user-attachments/assets/488852e7-2721-49e1-be51-5c140ec0f6f4" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Baseline which accounts are allowed to authenticate remotely. Any admin-capable account logging in from a public IP should be treated as high severity and immediately correlated with subsequent process, registry, and network activity.

</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: Attacker Geographic Attribution</strong></summary>

### 🎯 Objective
Determine the geographic region from which the attacker operated by enriching the public IP addresses associated with the remote session activity.

### 📌 Finding
The attacker authenticated and interacted with CH-OPS-WKS02 using a consistent public IP address. External IP geolocation enrichment confirms that this IP resolves to Vietnam, specifically the Hanoi region.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ch-ops-wks02 |
| Remote IP | 104.164.168.17 |
| Country | Vietnam |
| Region / City | Hanoi |
| Latitude | 21.0184 |
| Longitude | 105.8461 |

### 💡 Why it matters
Geographic attribution helps distinguish between legitimate administrative access and adversary-controlled infrastructure. In this case, the remote session originated from a foreign geographic region inconsistent with normal CorpHealth operations. This supports the conclusion that the activity was attacker-driven rather than internal administration.

**MITRE ATT&CK Mapping:**  
- **TA0001 – Initial Access**  
- **TA0011 – Command and Control**

Understanding the attacker’s geographic origin assists in scoping the intrusion, identifying potential access vectors, and informing response actions such as IP blocking, credential resets, and regional risk assessment.

### 🔧 KQL Query Used
```
print ip_location=geo_info_from_ip_address('104.164.168.17')
```
### 🖼️ Screenshot
<img width="741" height="355" alt="image" src="https://github.com/user-attachments/assets/c8e1a6da-3e8b-49da-965a-f71bac259b8e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When native geo-enrichment is unavailable in Defender, analysts should enrich public IPs using external tooling or IP intelligence sources. Repeated remote access from foreign regions—especially when paired with credential abuse and remote sessions—should be treated as high-confidence intrusion indicators and correlated with authentication and persistence telemetry.

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
