# Challenge 1: Dropper Dawn - Attack Map

## MITRE ATT&CK Technique Mapping

### Initial Access

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Social engineering via malicious installer link | High | Dropper execution requires user interaction |
| T1195.003 | Supply Chain Compromise: Compromised Software | Fake Windows Update distributing dropper | High | Masquerades as legitimate Windows Update |

**Initial Access Evidence**: Malware requires user execution - typical delivery via phishing links, malicious downloads, or compromised websites.

---

### Execution

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Creates scheduled task "WindowsUpdateClient" | Medium | Optional execution method |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Payload named "wupdater.exe" in System32 | High | Mimics Windows Update service |

**Execution Flow**:
1. User executes dropper (e.g., `InstallUpdate.exe`)
2. Dropper establishes registry Run key
3. Dropper executes payload immediately via CreateProcessA/W
4. On reboot, Windows reads Run key and auto-executes payload

---

### Persistence

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1547.001** | **Boot or Logon Autostart Execution: Registry Run Keys** | **HKLM\...\Run\WindowsUpdate** | **High** | **PRIMARY PERSISTENCE METHOD** |
| T1547.010 | Boot or Logon Autostart Execution: Scheduled Task | Scheduled task variant | Medium | Secondary method |
| T1547.004 | Boot or Logon Autostart Execution: Winlogon Helper DLL | Potential variant | Low | Not confirmed in primary sample |

**Persistence Indicators**:
- Registry Value: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` → `WindowsUpdate` = `C:\Windows\System32\wupdater.exe`
- Alternative: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Scheduled Task: `\Microsoft\Windows\WindowsUpdate\WindowsUpdateClient`
- Startup Folder: `C:\Users\[User]\AppData\Roaming\...\Startup\wupdater.exe`

---

### Privilege Escalation

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Possible elevation via token impersonation | Medium | Depends on execution context |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Achieves SYSTEM privileges on next boot | High | Run key → SYSTEM context via WinLogon |

**Privilege Escalation Path**:
1. Initial dropper execution: User privileges
2. UAC bypass (if needed): Escalate to Administrator
3. Registry modification: Write to HKLM (requires admin)
4. Next boot: WinLogon executes payload as SYSTEM
5. Final payload runs with highest privilege

---

### Defense Evasion

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1036.005** | **Masquerading: Match Legitimate Name or Location** | **Process name "wupdater.exe"** | **High** | **Blends with Windows Update processes** |
| T1027 | Obfuscation: Binary Obfuscation | Likely packed/obfuscated dropper | Medium | Reduces detection effectiveness |
| T1036.003 | Masquerading: Rename System Utilities | Uses System32 path for legitimacy | High | Exploits trusted system directory |
| T1564.001 | Hide Artifacts: Hidden Files and Attributes | File marked as Hidden | High | Reduced visibility in Windows Explorer |
| T1112 | Modify Registry | Stealth modification of Run keys | High | Registry changes are persistent |

**Defense Evasion Tactics**:
- System32 placement → trusted directory
- Process name mimics Windows Update → blend with legitimate processes
- Hidden file attribute → reduced user visibility
- Registry modification → less monitored than DLL injection
- No obvious C2 or malicious behavior indicators

---

### Discovery

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1518 | Software Discovery | Check for antivirus/security tools | Medium | Likely GetModuleHandle() for AV detection |
| T1087 | Account Discovery | Enumerate local users/groups | Low | Depends on payload capabilities |

**Discovery Activities**:
- GetModuleHandle() to detect AV DLLs (e.g., ahnlab, kaspersky)
- Registry enumeration of security software keys
- Process enumeration for security processes

---

### Command and Control (C2)

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| N/A | N/A | **Dropper only - no direct C2** | N/A | **Payload likely establishes C2** |

**Notes**: The dropper itself does not establish C2 communication. However, the dropped payload is expected to communicate with command and control infrastructure. See Challenge 2 (Silent Beacon) for C2 analysis.

---

### Exfiltration

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| N/A | N/A | **No direct exfiltration in dropper** | N/A | **Likely payload capability** |

**Notes**: Dropper does not directly exfiltrate data. Payload likely implements data exfiltration post-exploitation.

---

### Impact

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1531 | Account Access Removal | Potential follow-on payload impact | Low | Not performed by dropper itself |
| T1561 | Disk Wipe | Potential ransomware payload | Low | Not performed by dropper itself |

**Impact Potential**:
- Dropper enables persistent malware execution
- Dropped payload could perform any action with SYSTEM privileges
- Follow-on attacks: ransomware, data theft, lateral movement, etc.

---

## Tactic Summary

| Tactic | Techniques Used | Confidence | Risk Level |
|--------|---|---|---|
| **Initial Access** | T1566.002, T1195.003 | High | High |
| **Execution** | T1053.005, T1036.005 | High | High |
| **Persistence** | **T1547.001 (Primary)** | **High** | **Critical** |
| **Privilege Escalation** | T1548.002, T1547.001 | High | Critical |
| **Defense Evasion** | T1036.005, T1027, T1112 | High | High |
| **Discovery** | T1518, T1087 | Medium | Medium |
| **C2** | None (dropper only) | N/A | N/A |
| **Exfiltration** | None (dropper only) | N/A | N/A |
| **Impact** | Enables payload execution | High | Critical |

---

## Attack Chain Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│ INITIAL ACCESS: Phishing / Compromised Download (T1566.002)   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ EXECUTION: User launches dropper (T1036.005 - Masquerading)    │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ PRIVILEGE ESCALATION: UAC Bypass (T1548.002)                    │
│ Dropper gains Administrator/SYSTEM context                      │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ PERSISTENCE: Registry Run Key Modification (T1547.001)          │
│ Creates: HKLM\...\Run\WindowsUpdate = C:\Windows\Sys...\wupa...│
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ FILE DROP: Payload written to System32 (T1036.005)             │
│ Target: C:\Windows\System32\wupdater.exe (Hidden attribute)    │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ IMMEDIATE EXECUTION: Payload launched as SYSTEM                 │
│ CreateProcessA/W(wupdater.exe)                                  │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ PERSISTENCE TRIGGER: Next system boot                           │
│ WinLogon reads Run key → Executes wupdater.exe as SYSTEM        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ PAYLOAD EXECUTION: Delivered malware executes                   │
│ Potential: C2, Ransomware, Lateral Movement, Data Theft         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Opportunities

### High Confidence Indicators
1. **Registry Modification Event**: Write to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
2. **File Creation**: `C:\Windows\System32\wupdater.exe` with Hidden attribute
3. **Process Execution**: Creation of "wupdater.exe" from suspicious source
4. **Process Ancestry**: wupdater.exe spawned from dropper or explorer.exe

### Medium Confidence Indicators
5. **Scheduled Task Creation**: Suspicious "WindowsUpdateClient" task
6. **Registry Enumeration**: Excessive registry reads from security software keys
7. **File Attributes**: File hiding operations on System32 executables

### Low Confidence Indicators
8. **Network Connections**: Depends on payload C2 behavior
9. **Memory Injection**: Depends on payload capabilities
10. **UAC Bypass Attempts**: Various bypass techniques (fodhelper, eventvwr, etc.)

---

## Remediation Mapping

| Technique | Remediation | Evidence Reference |
|---|---|---|
| T1547.001 | Delete Run registry key + file | `iocs.json` registry_keys |
| T1036.005 | Rename/move suspicious file | `report.md` Cleanup Steps |
| T1548.002 | Review admin account activity | Check 4688 events |
| T1027 | Run decryption/deobfuscation tools | N/A (payload dependent) |

---

**Analysis Date**: 2026-07-27  
**Challenge**: Ch1 - Dropper Dawn  
**Status**: Complete
