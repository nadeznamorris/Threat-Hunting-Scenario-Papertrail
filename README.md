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

**Observation:**  
During the hunt for suspicious HR-related activity, we scoped file events starting **17th August 2025** and identified that `n4thani3l-vm` had the highest activity, with **3 file event counts** linked to sensitive HR directories (`HR`, `HumanResources`, `Payroll`, `Benefits`). To further validate, we pivoted to process activity and observed an unusually high execution rate of **994 processes** on the same device within the period `2025-08-19T04:15:54` UTC – `2025-08-20T03:05:00` UTC, which strongly indicated abnormal behavior consistent with script or config drops. This correlation of targeted HR file access and elevated process activity pinpointed `n4thani3l-vm` as the source of the breach.

**KQL Query :**
```kusto
DeviceFileEvents
| where Timestamp >= datetime(2025-08-17)
| where FolderPath has_any ("HR", "HumanResources", "Payroll", "Benefits")
| summarize count() by DeviceName
| order by count_ desc
```

```kusto
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

**Why this matter :**  
Attackers frequently stage activity around HR and payroll data because it contains sensitive personal and financial information. Coupled with abnormally high process creation, these patterns are red flags for malicious script execution, data staging, or exfiltration attempts — making immediate investigation and containment critical.

---

### 🐚 Flag 1 - Initial PowerShell Execution Detection

**Objective:**  
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**What to Hunt:**  
Initial signs of PowerShell being used in a way that deviates from baseline usage.

**Strategy:**  
To uncover the initial intrusion point, we filtered **process execution events** `(DeviceProcessEvents)` specifically on the compromised host `n4thani3l-vm`. By pivoting on **PowerShell executions** and reviewing the earliest recorded activity, we isolated a suspicious process with creation time `2025-08-19T03:42:32.9389416Z`. This timestamp highlights the **first deviation from baseline PowerShell usage**, marking the attacker’s entry vector. Starting the hunt from the earliest trace ensures we capture the origin of compromise, which is crucial for reconstructing the attacker’s full activity chain.

**KQL Query :**
```DeviceProcessEvents
// where Timestamp >= datetime(2025-08-19)
| where DeviceName == "n4thani3l-vm"
// where ProcessCommandLine has_any ("HR", "HR_Policy_Update", "HRHostnames", "HumanResources")
| summarize by Timestamp, FileName, ActionType, ProcessCommandLine, FolderPath
```




