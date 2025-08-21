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
- **Observation:** To scope the intrusion, the first query targeted HR-related file paths (HR, HumanResources, Payroll, Benefits) across all available endpoints. The logic was to surface any machines showing interaction with sensitive HR directories during the incident window. Host `n4thani3l-vm` stood out, logging 3 unique access counts. This initial pivot established the system of interest and framed subsequent hunts around this endpoint.



**Screenshot:** `![Fig-01 — Initial PS Recon](./images/Fig-01-Initial-PS-Recon.png)`

---

