# Threat-Hunting-Scenario-Papertrail

A sudden promotion caught everyone off guard. **A mid-level employee, with no real achievements, suddenly rose in rank**. Whispers spread, but the truth was buried deeper — in the HR systems. **Audit logs were wiped, performance reports rewritten, and sensitive evaluations quietly stolen**. Someone was rewriting history from the inside.

Behind it all was an intruder who knew how to blend in: **PowerShell trickery, stealthy file manipulation, and careful obfuscation** hid their tracks. That’s where you step in. The mission is simple but critical: **trace the insider’s moves, expose the fake artifacts, and rebuild the timeline they tried to erase**. Only then can the hidden motive behind a promotion that should never have happened come fully into view.

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

## 🛡️ Flag 6 - Defender Policy Modification

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

## :alien: Flag 9 - Outbound Communication Test

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

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%209%20log.png" alt="Flag 9 log" height="240" />

**Why This Matter :**  
Outbound communication to uncommon destinations, like a `.net` **domain**, often signals **attacker reconnaissance or early exfiltration attempts**. Detecting these lightweight tests is critical because even minimal network activity can indicate that sensitive information might soon leave the environment. Early detection supports **proactive mitigation and containment**.

---

## :postbox: Flag 10 - Covert Data Transfer

**Objective :**  
Uncover evidence of internal data leaving the environment.

**Flag Value :**  
`3.234.58.20`

**What To Hunt :**  
Activity that hints at transformation or movement of local HR data.

**Strategy :**  
We queried `DeviceNetworkEvents` on the targeted VM for outbound connections initiated by processes like `ping.exe`, `powershell.exe`, `cmd.exe`, `curl.exe`, and `wget.exe`, or command lines containing `ping`, `Test-Connection`, `Invoke-WebRequest`, or `curl`. By reviewing the `RemoteIP` and ordering events by timestamp descending, we identified the **last unusual outbound connection attempt**. This allowed us to pinpoint the **specific IP** (`3.234.58.20`) used for covert data transfer testing.

**KQL Query :**  
```
DeviceNetworkEvents
| where DeviceName == "n4thani3l-vm"
| where InitiatingProcessFileName in~ ("ping.exe", "powershell.exe", "cmd.exe", "curl.exe", "wget.exe")
   or InitiatingProcessCommandLine has_any ("ping", "Test-Connection", "Invoke-WebRequest", "curl")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp desc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2010%20log.png" alt="Flag 9 log" height="240" />

**Why This Matters :**  
Detecting these outbound “pings” is critical because they can indicate covert testing of exfiltration channels. Even simple network requests may precede actual data transfer, so identifying the endpoints early helps prevent sensitive HR data from leaving the environment and supports timely response and containment.

---

## :door: Flag 11 - Persistence via Local Scripting

**Objective :**  
Verify if unauthorized persistence was established via legacy tooling.

**Flag Value :**  
`OnboardTracker.ps1`

**What To Hunt :**  
Use of startup configurations tied to non-standard executables.

**Strategy :**  
We queried `DeviceRegistryEvents` on the VM for registry changes involving `Run` and `RunOnce` keys, which are commonly abused for persistence. By focusing on `RegistryValueSet` and `RegistryKeyCreated` actions, we could **detect unauthorized startup configurations**. We then examined the `RegistryValueData` to identify any non-standard executables or scripts. This review revealed a suspicious entry pointing to `OnboardTracker.ps1`, confirming that persistence was established through a local PowerShell script.

**KQL Query :**  
```
DeviceRegistryEvents
| where DeviceName == "n4thani3l-vm"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any ("\\Run", "\\RunOnce")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2011%20log.png" alt="Flag 11 log" height="240" />

**Why This Matter :**  
Persistence via **autorun registry keys** ensures that malicious code executes whenever the system starts, allowing attackers to maintain long-term access. The use of a **PowerShell script disguised as a business tool** makes the persistence stealthy and difficult to detect. Identifying this technique is critical because it highlights an active backdoor that could allow attackers to **repeatedly re-enter the environment even after remediation steps**. Removing the registry value, investigating script origins, and checking for similar entries across other systems are essential to contain the threat.

---

## :dart: FLag 12 - Targeted File Reuse / Access

**Objective :**  
Surface the document that stood out in the attack sequence.

**Flag Value :**  
`Carlos Tanaka Evaluation`

**What To Hunt :**  
Repeated or anomalous access to personnel files.

**Strategy :**  
We queried `DeviceFileEvents` on the VM to track file activity related to HR and personnel data by filtering for file names and folder paths containing keywords such as `employee`, `hr`, `payroll`, `personnel`, `staff`, and `records`. By projecting key fields and ordering events by **timestamp**, we could identify repeated access patterns. This approach surfaced the file **“Carlos Tanaka Evaluation”** as the document of unusual and repeated interest, standing out in the attack sequence.

**KQL Query :**  
```
DeviceFileEvents 
| where DeviceName == "n4thani3l-vm"
| where FileName has_any ("employee", "hr", "payroll", "personnel", "staff", "records")
      or FolderPath has_any ("HR", "Employee", "Payroll", "Users", "Documents")
| summarize AccessCount = count() by Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by AccessCount desc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2012%20log.png" alt="Flag 12 log" height="240" />

**Why This Matter :**  
Repeated or anomalous access to a specific personnel file often signals the **attacker’s intent or motive**. In this case, targeting **“Carlos Tanaka Evaluation”** suggests a focus on sensitive employee information that could be exploited for **espionage, insider leverage, or financial gain**. Highlighting such files is critical because it provides defenders with **insight into the adversary’s objectives**, allowing for focused containment and deeper investigation.

---

## :ledger: Flag 13 - Candidate List Manipulation

**Objective :**  
Trace tampering with promotion-related data.

**Flag Value :**  
`df5e35a8dcecdf1430af7001c58f3e9e9faafa05`

**What To Hunt :**  
Unexpected modifications to structured HR records.

**Strategy :**  
We queried `DeviceFileEvents` for the VM to focus specifically on `FileModified` actions. By projecting relevant fields such as `FileName`, `FolderPath`, `InitiatingProcessCommandLine`, and `SHA1`, and ordering the results by **timestamp ascending**, we identified the **first modification event** for the targeted HR record. This approach confirmed the tampering activity and allowed us to capture the associated **SHA1 value:** `df5e35a8dcecdf1430af7001c58f3e9e9faafa05`.

**KQL Query :**
```
DeviceFileEvents
| where DeviceName == "n4thani3l-vm"
| where ActionType contains "FileModified"
| summarize by Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA1
| order by Timestamp asc 
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2013%20log.png" alt="Flag 13 log" height="240" />

**Why This Matter :**  
Modifications to structured HR files, especially those tied to promotions, indicate **data tampering or staging for exfiltration**. Attackers often manipulate or duplicate files before extraction to either cover tracks or alter outcomes. Detecting the **first instance of modification** is crucial, as it provides defenders with a **clear timeline of compromise** and ensures that the altered file version can be investigated, validated, and remediated.

---

## :broom: Flag 14 - Audit Trail Disruption

**Objective :**  
Detect attempts to impair system forensics.

**Flag Value :**  
`2025-08-19T04:55:48.9660467Z`

**What To Hunt :**  
Operations aimed at removing historical system activity.

**Strategy :**  
We queried `DeviceProcessEvents` on the VM for commands commonly associated with **audit trail disruption**, including `wevtutil``, Clear-EventLog`, `Clear-History`, `Remove-Item`, and `ConsoleHost_history`. By projecting fields like `Timestamp`, `ProcessCommandLine`, and `SHA256`, and sorting the results in **ascending order**, we identified the **first recorded attempt** to clear system logs and impair forensic visibility. This occurred at `2025-08-19T04:55:48.9660467Z`.

**KQL Query :**  
```
DeviceProcessEvents
| where DeviceName == "n4thani3l-vm"
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "Clear-History", "Remove-Item", "ConsoleHost_history")
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2014%20log.png" alt="Flag 14 log" height="240" />

**Why This Matter :**  
Clearing logs is a well-known **anti-forensic technique** used by attackers to erase evidence of their activity. Detecting the **first attempt to tamper** with logs is crucial because it marks the transition from **stealthy compromise** to **covering tracks**, directly impacting an investigation’s ability to reconstruct events. Early detection of such activity enables defenders to **preserve system evidence** and prioritize containment.

---

## :snowboarder: Flag 15 - Final Cleanup and Exit Prep

**Objective :**  
Capture the combination of anti-forensics actions signaling attacker exit.

**Flag Value :**  
`2025-08-19T05:08:11.8528871Z`

**What To Hunt :**  
Artifact deletions, security tool misconfigurations, and trace removals.

**Strategy :**  
We ran a `union` query across `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceRegistryEvents` on the targeted VM to capture a broad view of potential **anti-forensics and cleanup actions**. Filters were applied to identify suspicious file names (such as `employee`, `hr`, `sysmon`, `history`, `log`), commands associated with log clearing or artifact deletion (like `wevtutil`, `Clear-EventLog`, `Clear-History`, `Remove-Item`, `EmptySysmonConfig.xml`), and registry keys linked to persistence or security tools (`Policies`, `Defender`, `Run`). By projecting relevant fields and sorting by **descending timestamp**, we pinpointed the **last attempt at cleanup and exit prep** at `2025-08-19T05:08:11.8528871Z`.

**KQL Query :**
```
union DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents
| where DeviceName == "n4thani3l-vm"
| where FileName has_any ("employee", "hr", "sysmon", "history", "log")
   or ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "Clear-History", "Remove-Item", "EmptySysmonConfig.xml")
   or RegistryKey has_any ("Policies", "Defender", "Run")
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, RegistryKey, RegistryValueName
| order by Timestamp desc
```

<img src="https://github.com/nadeznamorris/Threat-Hunting-Scenario-Papertrail/blob/main/Flag%2015%20log.png" alt="Flag 15 log" height="240" />

**Why This Matter :**  
Final cleanup actions are critical indicators of **attacker exit strategy**. These behaviors include **artifact deletion, tampering with logging, and disabling security controls**, all aimed at erasing forensic evidence and ensuring persistence traces are removed. Detecting the **last cleanup attempt** is essential for **defining the attack timeline**, preserving evidence before it’s lost, and ensuring remediation covers not only the intrusion but also the **forensic obfuscation techniques** used by the adversary.

---

## Summary
By the close of the investigation, the pattern became clear. **Credentials had been harvested, HR files accessed and altered, persistence planted, and outbound channels tested**. Along the way, we saw **Defender settings tampered with, audit trails disrupted, and promotion records rewritten**. Each action on its own could look routine — but together they painted a picture of an insider carefully covering their tracks.

Through **systematic threat hunting across process, file, registry, and network telemetry**, we were able to **reconstruct the attacker’s timeline** and expose the motive behind a promotion that should never have happened. What looked like an unexplained career jump was really the end result of **credential theft, data tampering, and anti-forensic cleanup**.

In the end, the breach showed us how **ordinary business artifacts can be weaponized** and how only **proactive, correlated hunting** can surface the truth buried beneath the noise.

---

## 🧩 MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique                                      | ID            | Description                                                                   |
| ---- | ---------------------------------------------------- | ------------- | ----------------------------------------------------------------------------- |
| 1    | Command and Scripting Interpreter: PowerShell        | **T1059.001** | Initial suspicious PowerShell execution used to establish entry.              |
| 2    | System Information Discovery                         | **T1082**     | Local account enumeration via `Get-LocalUser` and group queries.              |
| 3    | Permission Groups Discovery: Local Groups            | **T1069.001** | Checking membership of the Administrators group for privilege reconnaissance. |
| 4    | System Owner/User Discovery                          | **T1033**     | Session enumeration with `qwinsta.exe` to identify active logons.             |
| 5    | Impair Defenses: Disable or Modify Tools             | **T1562.001** | Disabling Windows Defender real-time monitoring via PowerShell.               |
| 6    | Modify Registry                                      | **T1112**     | Setting `DisableAntiSpyware` registry value to weaken defenses.               |
| 7    | OS Credential Dumping                                | **T1003**     | Dumping LSASS-related memory under disguise of HR-themed file.                |
| 8    | Data from Local System                               | **T1005**     | Inspection of dumped artifacts (`HRConfig.json`) with local tools.            |
| 9    | Application Layer Protocol: Web Traffic              | **T1071.001** | Outbound communication to `.net` domain via lightweight requests.             |
| 10   | Application Layer Protocol: ICMP                     | **T1071.004** | Covert data transfer attempt using ICMP ping to `3.234.58.20`.                |
| 11   | Boot or Logon Autostart Execution: Registry Run Keys | **T1547.001** | Persistence established with autorun script `OnboardTracker.ps1`.             |
| 12   | Data from Information Repositories                   | **T1213**     | Repeated access to sensitive personnel file (`Carlos Tanaka Evaluation`).     |
| 13   | Data Manipulation                                    | **T1565**     | Modification of candidate evaluation list to alter promotion outcome.         |
| 14   | Indicator Removal on Host: Clear Windows Event Logs  | **T1070.001** | First audit trail disruption with `wevtutil` and history clearing.            |
| 15   | Indicator Removal on Host                            | **T1070**     | Final cleanup and exit prep: deletion, misconfigurations, trace removals.     |

---

## 🛠️ Remediation Recommendations

- **Isolate compromised host** (`n4thani3l-vm`) immediately to prevent further spread.  
- **Reset local and domain credentials** for accounts potentially exposed via LSASS dumping.  
- **Re-enable and enforce Defender/AV protections**, restoring tampered registry keys (`DisableAntiSpyware`, `Set-MpPreference`).  
- **Remove persistence mechanisms** (e.g., autorun `OnboardTracker.ps1`) and inspect for similar entries across endpoints.  
- **Block outbound connections** to identified suspicious IPs (`3.234.58.20`) and TLDs (`.net`).  
- **Restore and validate HR files** (e.g., `Carlos Tanaka Evaluation`, candidate lists) to ensure integrity.  
- **Harden PowerShell usage** via constrained language mode, logging, and just-in-time admin rights.  
- **Increase monitoring for anti-forensic activity**, e.g., log clearing (`wevtutil`, `Clear-History`).  
- **Review and tighten access controls** around sensitive HR directories.  
- **Conduct enterprise-wide threat hunt** for similar indicators (registry changes, outbound traffic patterns, HR-themed artifacts).  
