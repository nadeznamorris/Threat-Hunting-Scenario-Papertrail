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

### :bust_in_silhouette: Flag 4 - Active Session Discovery

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

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%204%20log%202.png" alt="Flag 4 log" height="220" />

**Why This Matter :**  
Active session enumeration enables attackers to identify **who is currently logged in** and potentially hijack or impersonate those sessions. By blending into existing sessions, adversaries can avoid spawning new, suspicious processes and maintain stealth. Catching the use of `qwinsta.exe` is important because it marks the attacker’s intent to remain hidden while piggybacking on legitimate user activity.

---

### :unlock: Flag 5 - Defender Configuration Recon

**Objective :**  
Expose tampering or inspection of AV defenses, disguised under HR activity.

**Flag Value :**  
`"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"`

**What To Hunt :**  
Can be PowerShell related activity.

**Strategy :**  
To detect tampering with security defenses, we queried both **process and registry event**s using the `union` operator, which allowed us to combine multiple event tables (`DeviceProcessEvents`, `DeviceRegistryEvents`) into a single result set. This ensured we didn’t miss activity that could occur at either the process execution or registry modification level. Filtering for commands tied to Windows Defender inspection or manipulation (e.g., `Set-MpPreference`, `DisableRealtimeMonitoring`, `sc stop windefend`), we identified the suspicious execution:

`"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"`

This showed clear attempts to disable real-time monitoring while dropping a malicious payload script.

**KQL Query :**  
```
union DeviceProcessEvents, DeviceRegistryEvents
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("MpCmdRun", "Get-MpComputerStatus", "Set-MpPreference", "Add-MpPreference", "DisableRealtimeMonitoring", "RemoveDefinitions", "sc stop windefend")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%205%20log.png" alt="Flag 5 log" height="220" />

**Why This Matter :**  
Tampering with Defender settings signals an attacker’s effort to **evade detection and establish persistence**. By turning off protections under the guise of normal HR tooling, they create a blind spot for malicious payloads to execute unhindered. Spotting this activity early is critical, as once defenses are weakened, attackers can escalate their intrusion without triggering standard endpoint alerts.

---

## :hammer: Flag 6 - Defender Policy Modification

**Objective :**  
Validate if core system protection settings were modified.

**Flag Value :**  
`DisableAntiSpyware`

**What To Hunt :**  
Policy or configuration changes that affect baseline defensive posture.

**Strategy :**  
To confirm whether endpoint protections were weakened, we pivoted into **registry activity** using `DeviceRegistryEvents` scoped to `n4thani3l-vm`. By filtering on keys related to Windows Defender, we surfaced modification attempts tied to security policy. Projecting fields such as `RegistryKey`, `RegistryValueName`, and `RegistryValueData` allowed us to pinpoint the exact change, where the registry value `DisableAntiSpyware` was modified. Tracking this field is essential because it directly impacts whether the system runs with active anti-spyware protections.

**KQL Query :**  
```
DeviceRegistryEvents
| where DeviceName == "n4thani3l-vm"
| where RegistryKey has "Windows Defender"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%206%20log.png" alt="Flag 6 log" height="240" />

**Why This Matter :**  
Changing the `DisableAntiSpyware` registry value effectively turns off a core layer of Windows Defender protection. This is a strong indicator of tampering, as attackers often disable built-in defenses to avoid detection and run their payloads unhindered. Identifying such modifications early ensures defenders can **restore security baselines** and prevent attackers from operating in a weakened security environment.

---

## :moneybag: Flag 7 - Access to Credential-Rich Memory Space

**Objective :**  
Identify if the attacker dumped memory content from a sensitive process.

**Flag Value :**  
`HRConfig.json`

**What To Hunt :**  
Uncommon use of system utilities interacting with protected memory.

**Strategy :**  
To detect credential harvesting attempts, we investigated suspicious interactions with **protected memory** on `n4thani3l-vm`. Using `DeviceProcessEvents`, we filtered for command-line artifacts tied to dumping LSASS or related processes (`lsass`, `procdump`, `MiniDump`, `comsvcs.dll`, `lsass.dmp`). By projecting process details alongside file names and hashes, we identified that the attacker’s activity was linked with the HR-themed file `HRConfig.json`, showing how malicious payloads were disguised under business-relevant naming to avoid scrutiny.

**KQL Query :**  
```
DeviceProcessEvents
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("lsass", "procdump", "MiniDump", "comsvcs.dll", "lsass.dmp")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%207%20log.png" alt="Flag 7 log" height="250" />

**Why This Matter :**  
Memory dumping of **LSASS or similar processes** is a direct path to extracting credentials, giving attackers the keys to escalate privilege and move laterally. The presence of a file like `HRConfig.json` in this context shows deliberate masquerading, blending malicious actions with trusted HR workflows. Detecting such misuse is critical, because once credentials are stolen from memory, attackers can impersonate legitimate users and expand control across the environment.

---

## :page_with_curl: Flag 8 - File Inspection of Dumped Artifacts

**Objective :**  
Detect whether memory dump contents were reviewed post-collection.

**Flag Value :**  
`"notepad.exe" C:\HRTools\HRConfig.json`

**What To Hunt :**  
Signs of local tools accessing sensitive or unusually named files.

**Strategy :**  
We queried `DeviceProcessEvents` for any processes accessing the previously identified sensitive file `HRConfig.json`. By filtering for the specific `DeviceName` and examining the `ProcessCommandLine` for references to the file, we were able to detect whether local applications (like `notepad.exe`) were used to open or review dumped memory artifacts. This leveraged prior findings about the file involved in credential-rich memory access

**KQL Query :**  
```
DeviceProcessEvents
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("HRConfig.json")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%208%20log.png" alt="Flag 8 log" height="250" />

**Why This Matters :**  
Detecting post-dump inspection is crucial because **dumping memory alone doesn’t compromise sensitive data**—an attacker must review the contents to extract valuable information. Identifying the use of local tools accessing unusually named or sensitive files helps confirm **adversary behavior beyond collection**, informing response and mitigation steps.

---

## Flag 9 - Outbound Communication Test

**Objective :**  
Catch network activity establishing contact outside the environment.

**Flag Value :**  
`.net`

**What To Hunt :**  
Lightweight outbound requests to uncommon destinations.

**Strategy :**  
We analyzed `DeviceNetworkEvents` on the targeted VM for outbound connections initiated by `powershell.exe`, `cmd.exe`, `curl.exe`, `wget.exe`, and `bitsadmin.exe`. By inspecting the `RemoteUrl` and `RemoteIP`, we specifically identified connections targeting the `.net` **TLD**, which is unusual for internal operations. Highlighting the **.net usage** helped pinpoint suspicious network activity before any potential data exfiltration.

**KQL Query :**  
```
DeviceNetworkEvents
| where DeviceName == "n4thani3l-vm"
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Protocol, RemotePort
| order by Timestamp asc
```


**Why This Matter :**  
Outbound communication to uncommon destinations, like a `.net` **domain**, often signals **attacker reconnaissance or early exfiltration attempts**. Detecting these lightweight tests is critical because even minimal network activity can indicate that sensitive information might soon leave the environment. Early detection supports **proactive mitigation and containment**.
