# Threat-Hunting-Scenario-Papertrail

An attacker blended routine HR activity with discovery, defense evasion, and cleanup on Windows host **`n4thani3l-vm`**. The sequence began with **PowerShell-based reconnaissance**, progressed through **local admin discovery** and **session enumeration**, then **tampered with Microsoft Defender** before testing **outbound connectivity** and laying **persistence** via autorun keys. Targeted access to **personnel documents** and **promotion artifacts** was observed, followed by deliberate **audit-trail disruption** (command history, event logs, and telemetry). The activity window closes with a coordinated **final clean-up**.

:key: **Key Calls:**
- Privileged group check: `"powershell.exe" net localgroup Administrators`
- Session enumeration: `qwinsta.exe`
- Defender tampering: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Policy modification: registry value **`DisableAntiSpyware`**
- HR-themed artifact: `HRConfig.json` (opened via `notepad.exe`)
- Outbound test: domain **TLD `.net`**, later **ICMP** to **`3.234.58.20`**
- Persistence: autorun invoking **`OnboardTracker.ps1`**
- Heavily accessed personnel doc: **`Carlos Tanaka Evaluation`**
- Candidate list manipulation (first modified **SHA1**): `df5e35a8dcecdf1430af7001c58f3e9e9faafa05`
- First audit clear: **2025-08-19T04:55:48.9660467Z**; Last cleanup: **2025-08-19T05:08:11.8528871Z**

---

## 🛰️ Environment & Data Sources
- **Host:** `n4thani3l-vm` (Windows endpoint)
- **Telemetry:** Microsoft 365 Defender Advanced Hunting tables:
  - `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`
- **Timeframe:** 2025-08-17 → 2025-08-20 (UTC)  

---

## :hourglass_flowing_sand: Attack Narrative (Chronological)

### :triangular_flag_on_post: Flag 0 - Starting Point

**Objective :**  
During the hunt for suspicious HR-related activity, we scoped file events starting **17th August 2025** and identified that `n4thani3l-vm` had the highest activity, with **3 file event counts** linked to sensitive HR directories (`HR`, `HumanResources`, `Payroll`, `Benefits`). To further validate, we pivoted to process activity and observed an unusually high execution rate of **994 processes** on the same device within the period `2025-08-19T04:15:54` UTC – `2025-08-20T03:05:00` UTC, which strongly indicated abnormal behavior consistent with script or config drops. This correlation of targeted HR file access and elevated process activity pinpointed `n4thani3l-vm` as the source of the breach.

**Flag Value :**  
`n4thani3l-vm`

**KQL Query :**
```
DeviceFileEvents
| where Timestamp >= datetime(2025-08-17)
| where FolderPath has_any ("HR", "HumanResources", "Payroll", "Benefits")
| summarize count() by DeviceName
| order by count_ desc
```

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-08-19T04:15:54.0914923Z)..datetime(2025-08-20T03:05:00.6841797Z))
| summarize ProcessCount = count() by DeviceName
| order by ProcessCount asc
```

<p float="left">
  <img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Starting%20point%200.png" height="120" />
  &nbsp;&nbsp;&nbsp;
  <img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%200%20-%201.png" height="120" />
</p>

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Starting%20point%20vm.png" alt="Starting point vm" height="550" />

**Why This Matter :**  
Attackers frequently stage activity around HR and payroll data because it contains sensitive personal and financial information. Coupled with abnormally high process creation, these patterns are red flags for malicious script execution, data staging, or exfiltration attempts — making immediate investigation and containment critical.

---

### 🐚 Flag 1 - Initial PowerShell Execution Detection

**Objective:**  
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**Flag Value :**  
`2025-08-19T03:42:32.9389416Z`

**What To Hunt:**  
Initial signs of PowerShell being used in a way that deviates from baseline usage.

**Strategy:**  
To uncover the initial intrusion point, we filtered **process execution events** `(DeviceProcessEvents)` specifically on the compromised host `n4thani3l-vm`. By pivoting on **PowerShell executions** and reviewing the earliest recorded activity, we isolated a suspicious process with creation time `2025-08-19T03:42:32.9389416Z`. This timestamp highlights the **first deviation from baseline PowerShell usage**, marking the attacker’s entry vector. Starting the hunt from the earliest trace ensures we capture the origin of compromise, which is crucial for reconstructing the attacker’s full activity chain.

**KQL Query :**
```
DeviceProcessEvents
// where Timestamp >= datetime(2025-08-19)
| where DeviceName == "n4thani3l-vm"
// where ProcessCommandLine has_any ("HR", "HR_Policy_Update", "HRHostnames", "HumanResources")
| summarize by Timestamp, FileName, ActionType, ProcessCommandLine, FolderPath
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%201%20log.png" alt="Flag 1 log" height="220" />

**Why This Matter :**  
Identifying the **first suspicious PowerShell execution** on `n4thani3l-vm` at `2025-08-19T03:42:32.9389416Z` matters because it marks the attacker’s initial entry point, giving us the root of the intrusion timeline. Catching this earliest trace is critical to understand how the breach began and to prevent misinterpreting later activity as isolated. The use of the `whoami` command right after entry indicates the attacker was **validating their access level and privileges**, a common first step before deciding whether privilege escalation or further movement is needed.

---

### 📚 Flag 2 - Local Account Assessment

**Objective :**  
Map user accounts available on the system.

**Flag Value :**  
`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`

**What To Hunt :**  
PowerShell queries that enumerates local identities.

**Strategy :**  
To uncover attempts at local account enumeration, we scoped **PowerShell execution** (`powershell.exe`) within the timeframe **2025-08-17 to 2025-08-20** and filtered for commands explicitly tied to account discovery such as `Get-LocalUser` and `net localgroup Administrators`. This helped surface the exact process instance tied to suspicious account mapping, where the SHA256 value `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3` was observed. By projecting relevant fields like timestamp, device, parent process, and command line, we ensured both attribution and traceability of the activity.

**KQL Query :**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-08-17) .. datetime(2025-08-20))
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Get-LocalUser", "net localgroup Administrators")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%202%20log.png" alt="Flag 2 log" height="220" />

**Why This Matter :**  
Local account enumeration is a classic **reconnaissance step** intruders take after validating initial access. It enables them to identify privileged accounts for potential escalation or impersonation. Spotting this behavior early gives defenders a chance to respond before attackers leverage administrator accounts to widen their control across the system.

---

### 🏰 Flag 3 - Privileged Group Assessment

**Objective :**  
Identify elevated accounts on the target system.

**Flag Value :**  
`"powershell.exe" net localgroup Administrators`

**What To Hunt :**  
A method used to check for high-privilege users.

**Strategy :**  
To detect privileged group assessment activity, we focused on process events from `n4thani3l-vm` starting **2025-08-19**, filtering specifically for executions of `powershell.exe` and `schtasks.exe` which are commonly abused for reconnaissance and persistence. By projecting command-line arguments and timestamps in sequence, we uncovered the attacker’s use of the command: 
`"powershell.exe" net localgroup Administrators`
This revealed a direct attempt to enumerate members of the Administrators group, indicating privilege reconnaissance.

**KQL Query :**  
```
DeviceProcessEvents
| where Timestamp >= datetime(2025-08-19)
| where DeviceName == "n4thani3l-vm"
| where FileName has_any ("schtasks.exe", "powershell.exe")
| project Timestamp, FileName, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%203%20log.png" alt="Flag 3 log" height="220" />

**Why This Matter :**  
Enumerating the **Administrators group** is a clear indicator of an attacker mapping high-privilege accounts to plan escalation or impersonation. Once attackers know who has elevated rights, they can target those accounts for credential theft, persistence, or lateral movement. Detecting this early helps defenders stop the attack before control of privileged accounts is gained.

---

## Flag 4 - Active Session Discovery

**Objective :**  
Reveal which sessions are currently active for potential masking.

**Flag Value :**  
`qwinsta.exe`

**What to Hunt :**  
Might be session-enumeration commands.

**Strategy :**  
To detect session discovery activity, we hunted for commands commonly tied to enumerating user sessions (`qwinsta`, `quser`, `query user`, `query session`) on `n4thani3l-vm`. By extending a custom field (`SessionEnumCmd`) to extract the exact enumeration command used, we could clearly attribute the activity and identified the execution of `qwinsta.exe`, which was used to list currently active sessions. Projecting details such as timestamp, account, and initiating process helped validate the context of this activity.

**KQL Query :**  
```
DeviceProcessEvents
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("qwinsta","quser","query user","query session")
| extend SessionEnumCmd = extract(@'(qwinsta|quser|query\s+user|query\s+session)', 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, SessionEnumCmd, ProcessCommandLine
| order by Timestamp asc
```


