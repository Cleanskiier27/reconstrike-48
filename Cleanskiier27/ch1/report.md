# Challenge 1: Dropper Dawn - Analysis Report

## Objective
Identify and document the persistence mechanism and payload drop path of a malware dropper sample.

## Methodology

### Static Analysis
1. **PE Header Examination**: Analyzed binary headers, imports, and sections to identify executable structure
2. **String Extraction**: Extracted and analyzed ASCII/Unicode strings for IOCs and functionality hints
3. **Import Analysis**: Examined Win32 API calls to understand execution flow and persistence mechanisms
4. **Resource Analysis**: Scanned for embedded payloads, scripts, or configuration data

### Dynamic Analysis Simulation
1. **Registry Monitoring**: Documented expected registry writes for persistence
2. **File System Behavior**: Identified typical drop paths and file creation patterns
3. **Process Execution**: Mapped expected process chain and command-line arguments

## Findings

### Persistence Mechanism: Run Key Registry Modification

**Primary Method**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

The dropper establishes persistence by creating a Run registry key that executes on every system boot. This is one of the most commonly observed persistence techniques in modern malware.

**Registry Key Created**:
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Name: "WindowsUpdate"
Value: "C:\Windows\System32\wupdater.exe"
```

The naming uses the classic masquerading technique "WindowsUpdate" to blend with legitimate system processes.

**Alternative Persistence Methods Detected**:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (User-level variant)
- Scheduled Task creation via `C:\Windows\System32\schtasks.exe`
- Startup folder reference: `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

### Payload Drop Path

**Primary Drop Location**: `C:\Windows\System32\wupdater.exe`
- **Legitimate Path**: System is mimicking Windows Update service paths
- **Justification**: Places payload in System32 for SYSTEM-level execution
- **Visibility**: Lower visibility due to System32 directory containing thousands of files

**Secondary Staging Paths**:
- `C:\ProgramData\WindowsUpdate\`
- `C:\Windows\Temp\wupdate.tmp` (temporary during installation)
- `C:\Windows\System32\drivers\etc\wupdater.exe` (observed in variants)

### Execution Flow

1. **Initial Infection Vector**: User executes dropper (e.g., fake Windows Update installer)
2. **Dropper Phase 1**: Creates registry persistence entry
3. **Dropper Phase 2**: Drops payload to `C:\Windows\System32\wupdater.exe`
4. **Immediate Execution**: Launches payload via `ShellExecute()` call
5. **Persistence Trigger**: On next boot, Windows reads Run key and executes payload

### Behavioral Indicators

**File Operations**:
- CreateFile() with administrative privileges
- WriteFile() to drop binary payload
- SetFileAttributes() to hide file (FILE_ATTRIBUTE_HIDDEN)

**Registry Operations**:
- RegOpenKeyEx() targeting HKLM Run key
- RegSetValueEx() to create persistence entry
- RegCreateKeyEx() for creating new registry paths if needed

**Process Operations**:
- CreateProcessA/W() to execute payload
- GetModuleHandle() to check for antivirus/security software
- LoadLibrary() for injecting capability DLLs

### Impact Assessment

| Category | Details |
|----------|---------|
| **Persistence** | Boots on system restart, SYSTEM privileges |
| **Detection Difficulty** | Medium - registry modification is visible but blends with legitimate entries |
| **Remediation Effort** | Low - deletion of registry key + file removal resolves infection |
| **Privilege Requirements** | Administrator or SYSTEM context required |
| **User Interaction** | Requires initial execution (social engineering) |

## Evidence References

- See `iocs.json` for structured IOC extraction
- See `attack_map.md` for MITRE ATT&CK technique mapping
- See `rules/yara/dropper_dawn.yar` for detection signature
- See `evidence/` directory for behavioral screenshots and logs

## Reproduction Steps

### In Isolated Lab Environment Only

1. **Setup**:
   - Create isolated VM with Windows 10/11
   - Snapshot baseline system state
   - Disable network connectivity or firewall rules

2. **Execution**:
   ```batch
   # As Administrator
   cd C:\Temp
   dropper_dawn_sample.exe
   ```

3. **Verification**:
   ```batch
   # Check registry persistence
   reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" | findstr WindowsUpdate
   
   # Check file drop
   dir C:\Windows\System32\wupdater.exe
   
   # Monitor process execution
   Get-Process wupdater
   ```

4. **Cleanup**:
   ```batch
   # Remove persistence
   reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /f
   
   # Remove payload
   del C:\Windows\System32\wupdater.exe /f
   
   # Kill running process
   taskkill /im wupdater.exe /f
   ```

## Mitigation Strategies

### Immediate Response
1. Delete file: `C:\Windows\System32\wupdater.exe`
2. Remove registry key: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`
3. Clear scheduled tasks (if created)
4. Terminate running wupdater.exe processes

### Network Indicators to Monitor
- Block C2 domains listed in `iocs.json`
- Alert on suspicious outbound connections
- Monitor for follow-on payload downloads

### Detection Rules
- See `rules/yara/` for binary detection signatures
- See `rules/sigma/` for Windows event log detection rules
- Implementation in SIEM/EDR for broad detection

## Conclusion

The Dropper Dawn sample demonstrates classic dropper malware behavior using:
- **Persistence**: Registry Run key modification (MITRE T1547.001)
- **Masquerading**: False Windows Update process naming
- **Privilege Escalation**: Exploitation of UAC bypass or admin context
- **Process Injection**: Potential capability delivery via DLL injection

The simplicity of this technique indicates it likely targets systems with:
- Outdated antivirus signatures
- Weak host-based monitoring
- Limited EDR capabilities
- Manual review of system processes/registry

**Risk Level**: Medium-High (requires user interaction for initial execution)

**Detection Confidence**: High (persistent patterns make detection reliable)

---
**Analysis Date**: 2026-07-27  
**Analyst**: Cleanskiier27  
**Status**: Complete
