# Challenge 2: Silent Beacon - Attack Map

## MITRE ATT&CK Technique Mapping

### Command and Control

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1071.001** | **Application Layer Protocol: Web Protocols** | **HTTPS POST to beacon.update-services.net** | **High** | **PRIMARY C2 CHANNEL** |
| T1071.004 | Application Layer Protocol: DNS | DNS TXT record queries for commands | Medium | Fallback channel |
| T1095 | Non-Application Layer Protocol | Custom protocol on port 8080 | Medium | Alternative channel |
| T1092 | Communication Through Removable Media | N/A | Low | Potential offline mode |

**C2 Infrastructure Evidence**:
- Domains: `beacon.update-services.net`, `c2.windowsupdate-sync.com`, `updatecenter.cloud-monitor.io`
- IPs: `185.220.101.45`, `185.220.102.8` (bulletproof hosting)
- Ports: 443 (HTTPS), 8080 (HTTP), 53 (DNS)

---

### Exfiltration

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1041** | **Exfiltration Over C2 Channel** | **Data sent via HTTPS POST to /upload** | **High** | **PRIMARY EXFILTRATION** |
| T1020 | Automated Exfiltration | Scheduled exfiltration on command receipt | High | Data theft automation |
| T1030 | Data Transfer Size Limits | 512KB chunks for large files | Medium | Size-based exfiltration |
| T1048.003 | Exfiltration Over Alternative Protocol: HTTPS | Encrypted HTTPS channel | High | Primary transport |
| T1048.001 | Exfiltration Over Alternative Protocol: DNS | DNS TXT tunneling | Medium | Stealth channel |

**Exfiltration Indicators**:
- HTTP POST requests to `/update/upload` endpoint
- Base64 + gzip encoded output
- Large data transfers to bulletproof hosting
- Encrypted payloads in HTTP body

---

### Command and Control (Continued)

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1571 | Non-Standard Port | Port 443 for C2 (but custom protocol) | High | Encrypted C2 traffic |
| T1008 | Fallback Channels | Multiple domains and protocols | High | DNS, HTTP, HTTPS channels |
| T1573.002 | Encrypted Channel: Asymmetric Encryption | TLS + custom encryption | High | Defense evasion |
| T1008 | Fallback Channels | Automatic failover between domains | High | Resilience mechanism |

**Failover Mechanism**:
```
Primary:   beacon.update-services.net (185.220.101.45:443)
          ↓ (if fails)
Fallback:  c2.windowsupdate-sync.com (185.220.102.8:443)
          ↓ (if fails)
Tertiary:  updatecenter.cloud-monitor.io (fallback HTTP 8080)
          ↓ (if fails)
Emergency: DNS tunnel on port 53
```

---

### Remote Code Execution (RCE)

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1651** | **Acquire and Abuse Credentials** | **N/A** | **N/A** | **Not directly relevant** |
| T1609 | Container Administration Command | N/A | N/A | Not container environment |

**Note**: Remote code execution is implicit in beacon command reception:
- C2 sends `exec` command with arbitrary shell command
- Beacon executes command with SYSTEM privileges
- Output exfiltrated back to C2

---

### Defense Evasion

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1036.005 | Masquerading: Match Legitimate Name or Location | Beacon injected into svchost.exe | High | Process masquerading |
| T1027 | Obfuscation: Binary Obfuscation | Packed/obfuscated beacon DLL | High | Reduces AV detection |
| T1140 | Deobfuscate/Decode Files or Information | Base64 + XOR decoding in-memory | High | String obfuscation |
| T1197 | BITS Jobs | Potential file transfer method | Low | Alternative exfiltration |
| T1564.001 | Hide Artifacts: Hidden Files and Attributes | In-memory DLL injection | High | Fileless malware |
| T1562.012 | Indicator Removal: Clear Windows Event Logs | Potential clearing activity | Medium | Log tampering |

**Defense Evasion Tactics**:
- DLL injection into legitimate system process
- Encrypted communication blends with normal traffic
- Self-signed TLS certificates with legitimate-sounding names
- In-memory operation leaves minimal disk artifacts

---

### Discovery

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| **T1518** | **Software Discovery** | **`enum` command enumerates installed software** | **High** | **System profiling** |
| T1057 | Process Discovery | `enum processes` command | High | Process enumeration |
| T1120 | Peripheral Device Discovery | Potential USB device discovery | Low | Depends on payload |
| T1007 | System Service Discovery | Service enumeration via `enum` | Medium | Service profiling |

**Discovery Capabilities**:
- `enum scope=software` - Lists installed applications
- `enum scope=processes` - Lists running processes
- `enum scope=network` - Network configuration
- `enum scope=users` - Local user accounts
- `enum scope=shares` - Network shares

---

### Lateral Movement

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1570 | Lateral Tool Transfer | `download` command transfers tools | Medium | Depends on payload |
| T1570 | Lateral Tool Transfer | Payload staging via C2 | Medium | Multi-stage operation |

**Lateral Movement Potential**:
- `download` command retrieves additional tools
- Beacon with SYSTEM privileges enables lateral access
- Credential harvesting capability enables pass-the-hash

---

### Impact

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1531 | Account Access Removal | Potential via `exec` command | Low | Not direct impact |
| T1561 | Disk Wipe | Potential ransomware payload | Low | Not implemented in beacon |
| T1491 | Defacement | Potential via `exec` command | Low | No evidence observed |

**Potential Impact**:
- Full system compromise (SYSTEM privilege level)
- Data exfiltration (unbounded via C2 channel)
- Lateral movement (beachhead for network access)
- Ransomware deployment (capability to execute any command)
- Supply chain attacks (use as pivot point)

---

### Persistence

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|---|---|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Registry persistence (from Ch1) | High | Persistent beacon |
| T1547.010 | Boot or Logon Autostart Execution: Scheduled Task | WindowsUpdateClient task | High | Scheduled reinfection |
| T1547.012 | Boot or Logon Autostart Execution: Print Processors | Potential variant | Low | Rare technique |

**Persistence Chain**:
```
1. Initial dropper creates Run key
2. Run key launches wupdater.exe (loader)
3. Loader injects beacon DLL into svchost
4. Beacon maintains connection to C2
5. C2 can re-establish persistence if removed
6. Scheduled task provides backup persistence
```

---

## Attack Chain Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│ PERSISTENCE: Registry Run Key or Scheduled Task (T1547)         │
│ wupdater.exe executed on system boot                            │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ EXECUTION: wupdater.exe loads beacon DLL (T1036.005)            │
│ Target: svchost.exe (process injection)                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ DEFENSE EVASION: DLL injection into legitimate process          │
│ Beacon operates in-memory within svchost context                │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ COMMAND & CONTROL: HTTPS POST to C2 (T1071.001)                 │
│ Beacon checks in every 5 minutes to beacon.update-services.net  │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ DISCOVERY: Enumerate system and network (T1518, T1057)          │
│ C2 commands: enum processes, enum software, enum users          │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ COMMAND EXECUTION: Execute arbitrary commands (Remote Code Exe) │
│ exec cmd.exe /c [command] - runs with SYSTEM privilege         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ EXFILTRATION: Data sent to C2 (T1041)                           │
│ POST /update/upload - encrypted, compressed output              │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ LATERAL MOVEMENT & IMPACT: Full network compromise              │
│ Download tools, steal credentials, deploy ransomware            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tactic Summary

| Tactic | Techniques Used | Confidence | Risk Level |
|--------|---|---|---|
| **Command and Control** | **T1071.001, T1071.004, T1095** | **High** | **Critical** |
| **Exfiltration** | **T1041, T1048.003** | **High** | **Critical** |
| **Defense Evasion** | T1036.005, T1027, T1140 | High | High |
| **Discovery** | T1518, T1057 | High | Medium |
| **Persistence** | T1547.001, T1547.010 | High | Critical |
| **Lateral Movement** | T1570 | Medium | High |
| **Impact** | Varies by command | High | Critical |

---

## Detection Opportunities

### High Confidence Network Indicators
1. **Outbound HTTPS on Port 443**: Regular POST requests to bulletproof hosting
2. **Beacon Domain**: DNS queries to *.update-services.net
3. **Certificate Anomalies**: Self-signed cert with "Microsoft" issuer
4. **DNS TXT Queries**: Suspicious pattern of DNS TXT queries

### High Confidence Host Indicators
5. **Process Injection**: svchost.exe with unexpected network connections
6. **Registry Persistence**: WindowsUpdate Run key pointing to wupdater.exe
7. **Child Process Anomaly**: svchost.exe spawning cmd.exe/powershell.exe
8. **Privilege Elevation**: SYSTEM-context network activity

### Medium Confidence Indicators
9. **HTTP User-Agent**: Legitimate-sounding UA from system process
10. **JSON Payloads**: Encrypted base64 in HTTP POST body
11. **Scheduled Task**: Suspicious WindowsUpdateClient task
12. **File Operations**: Beacon config files in Windows\drivers\etc

---

## Remediation Priority

| Priority | Action | Evidence | Impact |
|---|---|---|---|
| **CRITICAL** | Block C2 IPs at firewall | 185.220.101.45, 185.220.102.8 | Stops C2 communication |
| **CRITICAL** | Block C2 domains at DNS | *.update-services.net, *.windowsupdate-sync.com | Stops domain resolution |
| **HIGH** | Kill svchost processes with network connections | svchost.exe listening on 443 | Stops beacon operation |
| **HIGH** | Remove registry persistence | Delete Run key, kill wupdater.exe | Stops re-execution |
| **HIGH** | Delete scheduled tasks | Remove WindowsUpdateClient task | Blocks backup persistence |
| **MEDIUM** | Hunt for injected DLLs | Search process memory | Prevent reinfection |
| **MEDIUM** | Reset credentials | Beacon may have harvested creds | Prevent lateral movement |

---

**Analysis Date**: 2026-07-27  
**Challenge**: Ch2 - Silent Beacon  
**Status**: Complete
