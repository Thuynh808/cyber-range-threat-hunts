![corphealth0](images/corphealth0.png)

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

## Investigation Sequence

| Stage                                   | Event                                                                                                           |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Initial Access                          | Suspicious logon to **CH-OPS-WKS02** from a public IP using account `chadmin`                                   |
| Post-Logon Discovery                    | Interactive session begins (GUI activity, file viewing, basic host recon)                                       |
| Beaconing                               | `MaintenanceRunner_Distributed.ps1` initiates outbound communication and later achieves a successful connection |
| Staging                                 | Inventory artifacts are written to CorpHealth-related directories, including a duplicate working copy in Temp   |
| Credential and System Tampering Signals | Registry activity under HKLM consistent with credential/agent manipulation patterns                             |
| Persistence Attempts                    | Scheduled task artifacts observed, plus short-lived Run key persistence behavior                                |
| Privilege Manipulation                  | ConfigAdjust and token modification telemetry observed (token privileges adjusted)                              |
| Tool Ingress                            | `curl.exe` retrieves an unsigned payload from a dynamic tunnel domain                                           |
| Execution and C2                        | Payload executes and attempts outbound connectivity to an external IP on a nonstandard port                     |
| Persistence via Startup                 | Executable is copied into a Startup folder path for logon execution                                             |
| Attribution Pivots                      | Remote session metadata and internal pivot indicators identify probable operator access path                    |


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

## Hunt Closure & Analyst Synthesis

The CorpHealth activity on **CH-OPS-WKS02** was not consistent with approved automation. The sequence demonstrates a clear intrusion chain: an initial suspicious logon (`chadmin`), early recon and credential file access, off-hours maintenance-script beaconing, staged diagnostic exports, registry manipulation and ephemeral persistence testing, token privilege modification, external tool ingress via **ngrok**, execution of an unsigned reverse-shell binary, outbound attempts to a nonstandard port, and persistence via Startup folder placement.

This progressed beyond “Operations Activity Review” into **confirmed malicious tradecraft**, with actionable IOCs and concrete containment priorities.

<details>
<summary><h2><strong>Appendix: Supporting Queries and Evidence (click to expand)</strong></h2></summary>

The following sections document the investigative queries used during the hunt, along with the corresponding evidence observed in endpoint telemetry to support each finding.

---

### Finding: Scoped Endpoint Identification (Flag 0)

```kql
let start = datetime(2025-11-05);
let end   = datetime(2025-11-25);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName has "ch"
| where InitiatingProcessCommandLine has "powershell" or ProcessCommandLine has "powershell"
| summarize devicee = count() by DeviceName
```

**Evidence observed:**
A single workstation surfaced with concentrated PowerShell-linked activity during the scoped mid-November window, allowing CH-OPS-WKS02 to be isolated as the primary device of interest.

**Why it matters:**
Correctly anchoring the investigation on the right endpoint prevents false narrative building and keeps all subsequent pivots consistent across process, network, file, and registry telemetry.

---

### Finding: Unique Maintenance Script on CH-OPS-WKS02 (Flag 1)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-24);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where InitiatingProcessCommandLine has "powershell" or ProcessCommandLine has "powershell"
| where ProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Evidence observed:**
`MaintenanceRunner_Distributed.ps1` appeared in PowerShell process telemetry on CH-OPS-WKS02 during the suspicious window, distinguishing it from baseline maintenance activity.

**Why it matters:**
The email scenario frames the investigation around “normal vs. unique.” A host-unique maintenance script is a high-signal pivot because it narrows the hunt to the specific execution chain responsible for downstream network and staging behaviors.

---

### Finding: First Outbound Communication by the Maintenance Script (Flag 2)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-24);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by TimeGenerated asc
```

**Evidence observed:**
The first network activity attributable to the maintenance script occurred at the earliest timestamp returned by this query, establishing when the script began communicating off-process.

**Why it matters:**
The scenario explicitly shifts from “script footprint” to “what it did.” This timestamp becomes the first network pivot in the investigation and marks the beginning of beacon-style behavior.

---

### Finding: Beacon Destination IP and Port (Flag 3)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-24);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by TimeGenerated asc
```

**Evidence observed:**
Network telemetry tied to the maintenance script revealed a consistent RemoteIP and RemotePort pairing representing the beacon destination (formatted as `IP:Port`).

**Why it matters:**
Per the email, this is the first concrete IOC leading off-host. Destination identification enables scoping (other devices contacting the same endpoint) and anchors later “beacon success” validation.

---

### Finding: Latest Successful Beacon Timestamp (Flag 4)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-30);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where RemoteIP == "127.0.0.1"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by TimeGenerated asc
```

**Evidence observed:**
A `ConnectionSuccess` event was recorded for the maintenance script’s network destination, and the newest success timestamp provided the “handshake moment” described in the scenario.

**Why it matters:**
The email frames this as the pivot point for follow-on staging. A successful outbound connection is the earliest point at which an operator could have interacted with the host through that channel.

---

### Finding: First Primary Staging Artifact Created (Flag 5)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where FolderPath contains "corphealth"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| where ActionType == "FileCreated"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**
The earliest `FileCreated` event under CorpHealth-related operational paths revealed the first staging artifact created during the attack window, including its full absolute path.

**Why it matters:**
The scenario explicitly transitions from network activity to “filesystem footprinting.” Identifying the first staged artifact clarifies what the operator prepared as a working output before heavier actions (collection, modification, transfer).

---

### Finding: SHA-256 of the Staged Artifact (Flag 6)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where FolderPath contains "corphealth"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| where ActionType == "FileCreated"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FolderPath, SHA256
```

**Evidence observed:**
File event metadata returned the SHA-256 hash associated with the staged artifact, providing a cryptographic fingerprint for the file created under the CorpHealth directory.

**Why it matters:**
Hashes support integrity validation, allow correlation across endpoints, and enable threat intel comparison. In the scenario’s terms, this is the point where the artifact becomes defensible evidence rather than “just a filename.”

---

### Finding: Duplicate Staging Artifact in Alternate Directory (Flag 7)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "ops.maintenance"
| where FolderPath contains "corphealth"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| where ActionType == "FileCreated"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FolderPath
```

**Evidence observed:**
A second, similarly named “inventory” artifact appeared in a different directory path during the same time horizon, indicating redundant staging behavior.

**Why it matters:**
The email frames this as an attacker “working copy” pattern. Similar names and timing but different paths strongly suggest intermediate processing or testing what locations are monitored.

---

### Finding: Suspicious Registry Key Activity (Flag 8)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| where InitiatingProcessAccountName == "ops.maintenance"
| where InitiatingProcessCommandLine has "powershell"
| project TimeGenerated, ActionType, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated
```

**Evidence observed:**
Registry events tied to PowerShell under the `ops.maintenance` context revealed an anomalous key path being created/touched during the credential-harvesting simulation stage.

**Why it matters:**
The scenario explicitly signals a shift to suspicious HKLM activity. Registry modifications under a normally “silent” operational account are a strong indicator of interactive misuse rather than baseline automation.

---

### Finding: Scheduled Task Persistence via TaskCache Tree (Flag 9)

```kql
let start = datetime(2025-11-01);
let end   = datetime(2025-11-30);
DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains "TaskCache" and RegistryKey contains "Tree"
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| order by TimeGenerated
```

**Evidence observed:**
The TaskCache Tree registry path showed creation/set activity consistent with a scheduled task being registered during the attack window.

**Why it matters:**
The email states a scheduled task was created and is not part of approved CorpHealth tasks. Scheduled tasks are durable persistence and frequently appear first through registry telemetry (TaskCache) even when other logging is sparse.

---

### Finding: Ephemeral Run-Key Persistence Attempt (Flag 10)

```kql
let start = datetime(2025-11-25);
let end   = datetime(2025-11-30);
DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| project TimeGenerated, ActionType, DeviceName, RegistryKey, RegistryValueName, PreviousRegistryValueName, RegistryValueData
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet" or ActionType == "RegistryKeyDeleted"
| where RegistryValueData has "ps1"
| order by TimeGenerated asc
```

**Evidence observed:**
Registry telemetry showed a Run-key style value associated with a PowerShell script path being created and later removed within the same general period.

**Why it matters:**
The scenario describes “ephemeral persistence” testing. This add-and-remove pattern is consistent with an operator probing what sticks, triggering once, and attempting to erase traces.

---

### Finding: First ConfigAdjust Privilege Escalation Event (Flag 11)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-30);
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (start .. end)
| where InitiatingProcessFileName has "powershell"
| where AdditionalFields contains "configadjust"
| order by TimeGenerated asc
```

**Evidence observed:**
An Application-log-derived DeviceEvents record included `configadjust` content in AdditionalFields, with the earliest timestamp representing the first observed privilege-adjustment attempt in the chain.

**Why it matters:**
The email frames this as the moment the actor probes privilege adjustments prior to riskier steps. This timestamp is a key anchor between registry persistence testing and later tooling ingress.

---

### Finding: AV Exclusion Attempt via PowerShell (Flag 12)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-05);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "powershell" or ProcessCommandLine has "powershell"
| where ProcessCommandLine contains "Exclusion"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

**Evidence observed:**
PowerShell process command lines contained exclusion-related arguments during the intrusion window, indicating an attempt to modify Defender scanning behavior.

**Why it matters:**
Per the scenario, “weakening host defenses” typically precedes staging and payload execution. Even a failed attempt demonstrates intent and helps explain why an attacker chose certain staging directories.

---

### Finding: PowerShell Encoded Command Execution (Flag 13)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-05);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "powershell" or ProcessCommandLine has "powershell"
| where ProcessCommandLine contains "encode"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

**Evidence observed:**
A PowerShell execution chain included `-EncodedCommand`, and decoding the Base64 payload yielded a plaintext command used to generate a token-like output.

**Why it matters:**
Encoded commands are a common obfuscation layer. In the scenario, this marks the transition from “maintenance-like scripting” into overt attacker tradecraft intended to hide intent from casual review.

---

### Finding: Token Privilege Modification Initiating ProcessId (Flag 14)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by TimeGenerated asc
```

**Evidence observed:**
DeviceEvents captured a token modification record with AdditionalFields describing privilege additions, and the event exposed the initiating process identifier.

**Why it matters:**
The email describes token modification as a PrivEsc indicator. Identifying the InitiatingProcessId ties the privilege change to a specific execution chain rather than treating it as an isolated “system event.”

---

### Finding: Token SID of Modified Security Principal (Flag 15)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, userid
| order by TimeGenerated asc
```

**Evidence observed:**
The token modification event returned the SID (user identifier) for the security principal whose token was modified.

**Why it matters:**
Attributing token changes to a specific SID clarifies whether the actor modified a low-priv user token or something higher-impact. It materially changes incident severity and scoping decisions.

---

### Finding: Ingress Tool Transfer (Dropped EXE) (Flag 16)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-30);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "curl.exe"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by TimeGenerated asc
```

**Evidence observed:**
File creation telemetry showed an executable being written to disk in close temporal proximity to curl activity, indicating inbound transfer of tooling.

**Why it matters:**
The email frames this as the transition from privilege manipulation to staging follow-on tooling. “curl → new .exe write” is a classic ingress pattern and a strong pivot for containment.

---

### Finding: External Download Source (ngrok) (Flag 17)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-30);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "curl.exe"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by TimeGenerated asc
```

**Evidence observed:**
Outbound network telemetry initiated by curl.exe contained a long, hyphenated RemoteUrl consistent with a dynamic tunnel domain used to retrieve the payload.

**Why it matters:**
Identifying the retrieval URL is essential for scoping across devices, blocking future ingress, and documenting external infrastructure used during the intrusion.

---

### Finding: Execution of the Staged Binary (Parent Process) (Flag 18)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-05);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "powershell" or ProcessCommandLine has "powershell"
| where ProcessCommandLine has "curl"
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed:**
Process telemetry associated the tool execution chain with a common Windows shell parent process, indicating user-like interactive launch behavior.

**Why it matters:**
The scenario explicitly notes interactive desktop access (not silent automation). Parent process context helps distinguish “tool executed by user/session” from “tool executed by service/scheduled job.”

---

### Finding: External IP Contacted by the Executable (Flag 19)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-30);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where RemotePort == "11746"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by TimeGenerated asc
```

**Evidence observed:**
Network events showed repeated outbound connection attempts to a single external RemoteIP on port 11746, originating from the suspicious executable’s activity window.

**Why it matters:**
This is the post-ingress command-and-control pivot. A consistent external IP and nonstandard port supports containment actions (block rules, retro-hunt for same destination across endpoints).

---

### Finding: Startup Folder Persistence Placement (Flag 20)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-12-05);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where FileName contains "exe"
| where FolderPath contains "start"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by TimeGenerated asc
```

**Evidence observed:**
A file event recorded an executable being written into a Windows Startup directory path, consistent with logon-triggered persistence.

**Why it matters:**
The scenario calls out Startup folder placement as a persistence mechanism. This confirms intent to survive reboots/logons and upgrades the incident from “suspicious maintenance” to durable compromise behavior.

---

### Finding: Remote Session Metadata (Device Label + Source IP) (Flags 21–22)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-30);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "curl.exe"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType, InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```

**Evidence observed:**
Multiple suspicious events shared consistent remote session metadata, including a stable remote session device label and a stable remote session IP value.

**Why it matters:**
The email frames this as proof of interactive remote access rather than local console use. Remote session metadata becomes a high-value pivot for linking process/file/network actions to the same operator presence.

---

### Finding: Internal Pivot Host Observed in Session Metadata (Flag 23)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-12-30);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "ch-ops-wks02"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType, InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName
| distinct InitiatingProcessRemoteSessionIP
```

**Evidence observed:**
Session metadata contained multiple RemoteSessionIP values, including an internal 10.x.x.x address consistent with an internal hop/pivot.

**Why it matters:**
The scenario explicitly raises the possibility of an internal pivot host. Identifying an internal RemoteSessionIP supports lateral movement scoping and investigation of upstream compromise.

---

### Finding: Earliest Suspicious Logon Timestamp (Flag 24)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-30);
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (start .. end)
| where LogonType contains "network"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| order by TimeGenerated asc
```

**Evidence observed:**
The earliest `LogonSuccess` event with a public RemoteIP established the first confirmed attacker foothold time on the endpoint.

**Why it matters:**
The email frames this as “the true beginning.” This timestamp anchors the entire timeline reconstruction and prevents later-stage artifacts from being misinterpreted as initial access.

---

### Finding: RemoteIP Used for Earliest Suspicious Logon (Flag 25)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-30);
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (start .. end)
| where LogonType contains "network"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| order by TimeGenerated asc
```

**Evidence observed:**
The same earliest suspicious logon record included a public RemoteIP value associated with the initial access event.

**Why it matters:**
This is the start of the intrusion path. It enables enrichment, blocking, and scoping for other authentication activity originating from the same infrastructure.

---

### Finding: Account Used for Earliest Suspicious Logon (Flag 26)

```kql
let start = datetime(2025-11-20);
let end   = datetime(2025-11-30);
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (start .. end)
| where LogonType contains "network"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where tolower(InitiatingProcessAccountName) !in ("system", "local service", "network service")
| order by TimeGenerated asc
```

**Evidence observed:**
The earliest suspicious logon event identified the AccountName used to authenticate during initial access.

**Why it matters:**
Account attribution is core to containment. Knowing which credentials were used informs credential reset scope, privileged access review, and whether the attack chain likely involved stolen operational/admin credentials.

---

### Finding: Geolocation Enrichment of Suspicious RemoteIP (Flag 27)

```kql
print geo = geo_info_from_ip_address("104.164.168.17")
```

**Evidence observed:**
Geo enrichment returned a consistent country/region and city associated with the suspicious IP, providing geographic context for the attacker’s origin.

**Why it matters:**
The scenario explicitly requests region attribution without external OSINT tools. Geo enrichment supports reporting, triage context, and correlation against other activity from the same region/provider range.

---

### Finding: First Process Executed After Initial Access (Flag 28)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-11-25);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**
The earliest post-logon process executions under the initial compromised account showed the first process launched during the attacker session.

**Why it matters:**
The email frames this as intent discovery. The first process provides immediate insight into whether the actor began with exploration, tooling, or environment validation.

---

### Finding: First File Accessed in the Session (Flag 29)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-11-25);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**
A GUI-driven process execution chain referenced the first file opened in the session, exposing an early access target aligned to credential discovery.

**Why it matters:**
The email calls this a priority indicator. Early file access often reveals goals (credentials/config), and it helps explain subsequent account usage and persistence attempts.

---

### Finding: Next Action After File Read (Recon Kickoff) (Flag 30)

```kql
let start = datetime(2025-11-23);
let end   = datetime(2025-11-25);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**
Immediately after the file-viewing activity, the next processes executed under the same session reflected the attacker’s next step (recon/validation), identifiable by the next FileName in the ordered output.

**Why it matters:**
The scenario frames this as “how did they leverage what they read.” Confirming the next action bridges the chain from credential access into active host enumeration.

---

### Finding: Next Account Accessed After Initial Enumeration (Flag 31)

```kql
let start = datetime('2025-11-23T03:11:00.6981995Z');
let end   = datetime(2025-11-25);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where tolower(AccountName) !in ("system", "local service", "network service")
| where DeviceName == "ch-ops-wks02"
| project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**
Process telemetry in the immediate post-enumeration window showed activity under a different account context, indicating a transition from the initial account to another user account.

**Why it matters:**
The email frames this as the point where the intrusion shifts from discovery to account-level interaction. Account switching is a key indicator of credential testing, lateral prep, or escalation in access.

</details>
