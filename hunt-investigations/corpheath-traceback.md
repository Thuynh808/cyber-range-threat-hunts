![corphealth0](images/corphealth0.gif)

# Threat Hunt Report - CorpHealth: Traceback

* **Hunt Name:** CorpHealth: Traceback
* **Author:** Thong Huynh
* **Date:** 2026-02-13
* **Environment:** Microsoft Defender for Endpoint (MDE) + Azure diagnostic/device logs (via Sentinel/LAW)
* **Hunt Type:** Timeline-driven, hypothesis-driven threat hunt (privileged account misuse)
* **Severity:** High (Confirmed unauthorized interactive activity and C2 tooling)

## Executive Summary

Historical telemetry review identified unauthorized, interactive activity on an operations workstation (**CH-OPS-WKS02**) spanning **November 23, 2025 through November 30, 2025 (UTC)**. Activity initially presented as routine CorpHealth maintenance but deviated from baseline behavior through anomalous script execution, off-hours network beacons, suspicious staging artifacts, registry modifications, token privilege manipulation, external tool ingress via an **ngrok** domain, and persistence via the Windows Startup folder.

The investigation determined the behavior was not consistent with approved automation frameworks. Instead, it reflected deliberate attacker tradecraft including credential access, privilege escalation simulation, defense weakening attempts, payload staging, and command-and-control establishment.

**Outcome:**

* Compromised endpoint activity confirmed (interactive + post-exploitation tooling)
* Persistence established (Startup folder)
* External infrastructure identified (ngrok domain + remote IP)
* Initial access path reconstructed (earliest logon, source IP, account used)

---

## Hunt Objective & Hypothesis

**Objective:**
Determine whether CorpHealth operational telemetry on **CH-OPS-WKS02** reflects authorized automation or misuse of privileged operational credentials.

**Hypothesis:**
If a privileged operational account or automation channel was misused, then telemetry will show off-hours interactive execution patterns inconsistent with baseline maintenance, including: unusual PowerShell script behavior, beaconing, staging artifacts, registry-based persistence/testing, token privilege modification, tool ingress from external infrastructure, and persistence via common user execution paths.

---

## Data Sources

| Data Source          | Platform                        |
| -------------------- | ------------------------------- |
| DeviceProcessEvents  | Microsoft Defender for Endpoint |
| DeviceNetworkEvents  | Microsoft Defender for Endpoint |
| DeviceFileEvents     | Microsoft Defender for Endpoint |
| DeviceRegistryEvents | Microsoft Defender for Endpoint |
| DeviceEvents         | Microsoft Defender for Endpoint |
| DeviceLogonEvents    | Microsoft Defender for Endpoint |

---

## Scope

* **Time Range:** `2025-11-23` to `2025-11-30` (UTC), anchored on first suspicious logon and latest successful beacon
* **Primary Host:** `CH-OPS-WKS02`
* **Accounts Observed in Chain:** `chadmin`, `ops.maintenance`
* **Remote Session Metadata:** Remote session device label `对手`, remote session IP(s) including `100.64.100.6` and internal `10.168.0.7`
* **External Infrastructure:** ngrok domain and external IP `13.228.171.119` (port `11746`)

---

## Methodology

This hunt followed a **behavior-first timeline reconstruction** approach:

1. Anchored scope on the flagged endpoint and off-hours maintenance window
2. Identified unique script execution tied to anomalous behavior
3. Correlated script → network activity to confirm beaconing and success timing
4. Pivoted from beacon confirmation into filesystem staging artifacts and integrity checks
5. Tracked registry modification patterns including scheduled task and Run-key activity
6. Validated privilege manipulation using token modification events in DeviceEvents
7. Identified payload ingress path (curl → external tunnel domain → dropped binary)
8. Confirmed persistence through Startup folder placement
9. Worked backward to reconstruct initial access (earliest logon, source IP, account)

---

## Investigation Timeline

| Timestamp (UTC)             | Event                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 2025-11-23 03:08:31.1849379 | **Earliest suspicious logon** to CH-OPS-WKS02 from `104.164.168.17` using account `chadmin`                             |
| 2025-11-23 (post-logon)     | First observed post-logon process: `explorer.exe`                                                                       |
| 2025-11-23 (early session)  | First file opened via GUI: `CH-OPS-WKS02 user-pass.txt`                                                                 |
| 2025-11-23 (follow-on)      | Recon begins: `ipconfig.exe` executed                                                                                   |
| 2025-11-23 03:46:08.400686  | **First outbound communication** attributed to `MaintenanceRunner_Distributed.ps1`                                      |
| 2025-11-23 03:47:21.8529749 | First Application event indicating **ConfigAdjust privilege escalation simulation**                                     |
| 2025-11-30 01:03:17.6985973 | **Latest successful beacon** (ConnectionSuccess) tied to the maintenance script                                         |
| 2025-11-xx to 11-xx         | First staging artifact created: `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`                |
| 2025-11-xx to 11-xx         | Duplicate staging artifact created: `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv` |
| 2025-11-xx to 11-xx         | Registry activity: `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent` touched/created            |
| 2025-11-xx to 11-xx         | Scheduled task registry tree created: `HKLM\...\Schedule\TaskCache\Tree\CorpHealth_A65E64`                              |
| 2025-11-xx to 11-xx         | Run key value created then removed: **RegistryValueName** = `MaintenanceRunner`                                         |
| 2025-11-xx to 11-xx         | Encoded PowerShell execution decoded to: `Write-Output 'token-6D5E4EE08227'`                                            |
| 2025-11-xx to 11-xx         | Token privilege modification: **InitiatingProcessId** `4888`, token SID `S-1-5-21-1605642021-30596605-784192815-1000`   |
| 2025-11-xx to 11-xx         | Tool ingress: executable dropped `revshell.exe` after `curl.exe` activity                                               |
| 2025-11-xx to 11-xx         | External download source (ngrok): `unresuscitating-donnette-smothery.ngrok-free.dev`                                    |
| 2025-11-xx to 11-xx         | Execution of unsigned binary: parent process `explorer.exe`                                                             |
| 2025-11-xx to 11-xx         | Outbound attempts by `revshell.exe` to `13.228.171.119:11746`                                                           |
| 2025-11-xx to 11-xx         | Persistence: Startup folder placement `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`       |

> Note: Several mid-chain timestamps were determined during the hunt but are not re-listed here until you paste the supporting KQL outputs into the Appendix.

---

## Key Findings

### Misuse of Maintenance Script for Beaconing

* **Unique script** on the host: `MaintenanceRunner_Distributed.ps1`
* Script initiated outbound communication at **2025-11-23T03:46:08.400686Z**
* Beacon destination observed: `127.0.0.1:8080`
* Latest successful connection was **2025-11-30T01:03:17.6985973Z**, establishing a clear pivot point for post-beacon actions.

### Staging of Operational Inventory Artifacts

* Primary staged artifact:

  * `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
  * SHA-256: `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`
* Secondary staged artifact (similar naming and timing, different location/hash):

  * `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`
* This pattern is consistent with intermediate processing or selective export preparation.

### Registry Activity Consistent With Unauthorized Configuration Changes

* Suspicious key touched/created:

  * `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
* Scheduled task persistence indicator via registry tree:

  * `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`
* Short-lived Run-key style persistence attempt:

  * **RegistryValueName:** `MaintenanceRunner` (added then removed)

### Privilege Manipulation and Token Modification

* Application event indicating a privilege/config adjustment simulation:

  * First observed at **2025-11-23T03:47:21.8529749Z**
* Token modification details:

  * **InitiatingProcessId:** `4888`
  * Token SID: `S-1-5-21-1605642021-30596605-784192815-1000`

### External Tool Ingress and Reverse Shell Behavior

* Dropped binary: `revshell.exe`
* Retrieved via `curl.exe` from ngrok domain:

  * `unresuscitating-donnette-smothery.ngrok-free.dev`
* Executed via `explorer.exe` (user-interactive pattern)
* Outbound attempts by binary:

  * Destination IP: `13.228.171.119` on port `11746`
* Persistence established via Startup folder:

  * `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

### Initial Access and Attribution Signals

* Remote session device label repeatedly observed: `对手`
* Remote session IP: `100.64.100.6`
* Internal pivot IP observed in remote session metadata: `10.168.0.7`
* Earliest suspicious logon:

  * **Timestamp:** `2025-11-23T03:08:31.1849379Z`
  * **RemoteIP:** `104.164.168.17`
  * **Account:** `chadmin`
* Geolocation enrichment for suspicious IP range indicated:

  * **Vietnam (Hanoi)**

---

## MITRE ATT&CK Mapping

| Tactic               | Technique                                                            | ID                 |
| -------------------- | -------------------------------------------------------------------- | ------------------ |
| Initial Access       | Valid Accounts                                                       | T1078              |
| Execution            | PowerShell                                                           | T1059.001          |
| Execution            | Command-Line Interface                                               | T1059.003          |
| Persistence          | Scheduled Task/Job                                                   | T1053              |
| Persistence          | Boot or Logon Autostart Execution (Startup Folder)                   | T1547.001          |
| Defense Evasion      | Obfuscated/Compressed Files and Information (EncodedCommand)         | T1027              |
| Defense Evasion      | Modify Registry                                                      | T1112              |
| Credential Access    | Credential Access (simulated via registry/tokens)                    | T1003 (contextual) |
| Privilege Escalation | Access Token Manipulation                                            | T1134              |
| Discovery            | System Network Configuration Discovery (ipconfig)                    | T1016              |
| Command and Control  | Application Layer Protocol / Web Services (tunneling infrastructure) | T1071 (contextual) |
| Command and Control  | Ingress Tool Transfer                                                | T1105              |

---

## Indicators of Compromise (IOCs)

| Type                    | Value                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------- |
| Hostname                | CH-OPS-WKS02                                                                        |
| Script                  | MaintenanceRunner_Distributed.ps1                                                   |
| Staging File            | `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`            |
| Staging File            | `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv` |
| File Hash (SHA-256)     | `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`                  |
| Dropped EXE             | revshell.exe                                                                        |
| Persistence Path        | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`         |
| External Domain         | unresuscitating-donnette-smothery.ngrok-free.dev                                    |
| External IP             | 13.228.171.119:11746                                                                |
| Initial Access RemoteIP | 104.164.168.17                                                                      |
| Remote Session Label    | 对手                                                                                  |
| Remote Session IP       | 100.64.100.6                                                                        |
| Internal Pivot IP       | 10.168.0.7                                                                          |
| Accounts                | chadmin, ops.maintenance                                                            |

---

## Response Actions

* Isolate CH-OPS-WKS02 (or validate it is no longer active / reimaged)
* Remove Startup persistence (`...\StartUp\revshell.exe`) and validate no additional autostarts exist
* Collect and preserve artifacts:

  * `revshell.exe` (original + Startup copy)
  * `MaintenanceRunner_Distributed.ps1`
  * both `inventory*.csv` staging files
* Reset credentials and rotate secrets for:

  * `chadmin`
  * `ops.maintenance`
  * any automation credentials tied to CorpHealth workflows
* Review scheduled tasks for unauthorized entries, especially those matching the `CorpHealth_*` naming convention but not present in approved baselines
* Block/alert on outbound connections to the identified ngrok domain and the external IP/port observed

---

## Detection Gaps & Improvements

**Observed gaps:**

* Maintenance script activity blended into “expected operations” due to naming and location similarity
* Successful beaconing and subsequent staging did not generate high-confidence alerts as isolated events
* External tunneling infrastructure (ngrok) was reachable from an ops workstation without strong policy guardrails

**Improvements:**

* Baseline-approved CorpHealth scripts per host, and alert on *new or unique* script names appearing on a single endpoint
* Alert on PowerShell `-EncodedCommand` usage outside signed automation frameworks
* Add detections for:

  * `curl.exe` used interactively on ops workstations
  * `.exe` written to user profile paths and executed shortly after download
  * Startup folder writes of executables
* Enrich and alert on remote session metadata fields when present (remote session label/IP correlation across multiple event types)
* Harden egress policies against tunneling services or require explicit allowlisting

---

## Lessons Learned

* “Operational maintenance” is a strong disguise for low-noise attacker activity because it naturally includes scripts, admin privileges, and scheduled execution
* Timeline anchoring on **first successful beacon** and **first suspicious logon** simplified the entire reconstruction
* Redundant staging artifacts (same theme, different hash/location) provided a reliable signal of hands-on attacker workflow
* Remote session metadata (label/IP) can be a powerful pivot when process/file/network telemetry alone is ambiguous

---

## Recommendations

* Enforce strict separation between:

  * automation-run privileged maintenance
  * interactive administrative actions
* Restrict interactive use of privileged operational accounts (deny interactive logon, require JIT/JEA patterns where applicable)
* Implement allowlisted script execution controls for CorpHealth directories
* Add outbound filtering or monitoring for tunneling services (ngrok and similar)
* Require signed scripts and centrally managed deployment for maintenance runners
* Periodically validate scheduled tasks and Startup folders for ops endpoints as part of continuous monitoring

---

<details>
<summary><h2><strong>Appendix: Supporting Queries and Evidence (click to expand)</strong></h2></summary>

Paste your KQL and screenshots here. Recommended structure (matches your template style):

### Finding: Unique Maintenance Script Identification (Flag 1)

```kql
// TODO: paste query
```

![corphealth1](images/corphealth1.png)

---

### Finding: First Outbound Communication Timestamp (Flag 2)

```kql
// TODO: paste query
```

![corphealth2](images/corphealth2.png)

---

### Finding: Beacon Destination and Success (Flags 3–4)

```kql
// TODO: paste query
```

![corphealth3](images/corphealth3.png)

---

### Finding: Staged Artifacts + Hash Verification (Flags 5–7)

```kql
// TODO: paste query
```

![corphealth4](images/corphealth4.png)

---

### Finding: Registry + Scheduled Task + Run Key Persistence (Flags 8–10)

```kql
// TODO: paste query
```

![corphealth5](images/corphealth5.png)

---

### Finding: Privilege Escalation and Token Modification (Flags 11, 14–15)

```kql
// TODO: paste query
```

![corphealth6](images/corphealth6.png)

---

### Finding: Ingress Tool Transfer, Execution, C2, and Startup Persistence (Flags 16–20)

```kql
// TODO: paste query
```

![corphealth7](images/corphealth7.png)

---

### Finding: Remote Session Source + First Logon Reconstruction (Flags 21–31)

```kql
// TODO: paste query
```

![corphealth8](images/corphealth8.png)

</details>

---

## Hunt Closure & Analyst Synthesis

The CorpHealth activity on **CH-OPS-WKS02** was not consistent with approved automation. The sequence demonstrates a clear intrusion chain: an initial suspicious logon (`chadmin`), early recon and credential file access, off-hours maintenance-script beaconing, staged diagnostic exports, registry manipulation and ephemeral persistence testing, token privilege modification, external tool ingress via **ngrok**, execution of an unsigned reverse-shell binary, outbound attempts to a nonstandard port, and persistence via Startup folder placement.

This progressed beyond “Operations Activity Review” into **confirmed malicious tradecraft**, with actionable IOCs and concrete containment priorities.
