/*
 * YARA Rule Collection for Blue Mirror Challenge (Ch5)
 * Comprehensive Detection: Dropper + Beacon Malware Family
 * Target: Windows PE Executables and DLLs
 * Date: 2026-07-27
 * Author: Cleanskiier27
 */

rule Dropper_WindowsUpdate_Masquerade {
    meta:
        description = "Detects dropper with Windows Update process masquerading"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1036.005,T1547.001"
        
    strings:
        $reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg_val = "WindowsUpdate" nocase
        $target = "wupdater.exe" nocase
        $api1 = "RegSetValueEx" nocase
        $api2 = "CreateProcessA" nocase
        $sys32 = "\\System32\\" nocase
        
    condition:
        uint16(0) == 0x5a4d and
        all of ($reg_path, $reg_val, $target) and
        (any of ($api1, $api2)) and
        $sys32
}

rule Beacon_C2_Infrastructure_Hardcoded {
    meta:
        description = "Detects hardcoded C2 domains in beacon binary"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1071.001"
        
    strings:
        $pe = "MZ"
        $domain1 = "beacon.update-services.net" nocase
        $domain2 = "c2.windowsupdate-sync.com" nocase
        $domain3 = "updatecenter.cloud-monitor.io" nocase
        $https = "https://" nocase
        $post = "/update/" nocase
        
    condition:
        $pe at 0 and
        (any of ($domain1, $domain2, $domain3)) and
        $https and
        $post
}

rule Beacon_Process_Injection_Signature {
    meta:
        description = "Detects beacon DLL injection into system processes"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1055"
        
    strings:
        $pe = "MZ"
        $alloc = "VirtualAllocEx" nocase
        $write = "WriteProcessMemory" nocase
        $thread = "CreateRemoteThread" nocase
        $target = "svchost" nocase
        $exec = "exec" nocase
        
    condition:
        $pe at 0 and
        (all of ($alloc, $write, $thread)) and
        $target
}

rule Malware_Family_Network_Beacon {
    meta:
        description = "Generic network beacon malware detection"
        author = "Cleanskiier27"
        severity = "high"
        
    strings:
        $pe = "MZ"
        $socket = "socket" nocase
        $connect = "connect" nocase
        $send = "send" nocase
        $json1 = "{\"" 
        $json2 = "\"command\""
        $interval = "Sleep" nocase
        $retry = "retry" nocase
        
    condition:
        $pe at 0 and
        (any of ($socket, $connect, $send)) and
        (any of ($json1, $json2)) and
        (any of ($interval, $retry))
}

rule Obfuscated_Dropper_Generic {
    meta:
        description = "Detects packed/obfuscated dropper patterns"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1027"
        
    strings:
        $pe = "MZ"
        $stub1 = {55 8B EC 83 EC}
        $stub2 = {FF 15 [4] 59}
        $xor_pattern = {[3-5] XOR [4-8] }
        $sparse_imports = { 0 0 0 0 0 0 0 0 }
        
    condition:
        $pe at 0 and
        (any of ($stub1, $stub2)) and
        #sparse_imports > 5
}

rule Credential_Stealing_Capability {
    meta:
        description = "Detects credential harvesting functionality"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1187"
        
    strings:
        $pe = "MZ"
        $api1 = "CredEnumerate" nocase
        $api2 = "LsaEnumerateLogonSessions" nocase
        $registry = "SAM" nocase
        $lsass = "lsass" nocase
        
    condition:
        $pe at 0 and
        (($api1 or $api2) and ($registry or $lsass))
}

rule Command_Execution_Capability {
    meta:
        description = "Detects arbitrary command execution functionality"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1651"
        
    strings:
        $pe = "MZ"
        $create_proc = "CreateProcessA" nocase
        $shell = "ShellExecute" nocase
        $cmd = "cmd.exe" nocase
        $powershell = "powershell.exe" nocase
        $timeout = "timeout" nocase
        
    condition:
        $pe at 0 and
        (any of ($create_proc, $shell)) and
        (any of ($cmd, $powershell)) and
        $timeout
}

rule Data_Exfiltration_Capability {
    meta:
        description = "Detects data exfiltration functionality"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1041"
        
    strings:
        $pe = "MZ"
        $file_read = "ReadFile" nocase
        $http_write = "HttpSendRequestA" nocase
        $crypto = "CryptEncrypt" nocase
        $compress = "compress" nocase
        $upload = "upload" nocase
        $exfil = "exfil" nocase
        
    condition:
        $pe at 0 and
        ($file_read or $http_write) and
        (any of ($crypto, $compress)) and
        (any of ($upload, $exfil))
}

rule Persistence_Registry_Modification {
    meta:
        description = "Detects registry-based persistence mechanisms"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1547.001"
        
    strings:
        $pe = "MZ"
        $reg_api = "RegSetValueEx" nocase
        $reg_path1 = "\\CurrentVersion\\Run" nocase
        $reg_path2 = "\\CurrentVersion\\RunOnce" nocase
        $persist_value = "WindowsUpdate" nocase
        
    condition:
        $pe at 0 and
        $reg_api and
        (any of ($reg_path1, $reg_path2)) and
        $persist_value
}

rule Scheduled_Task_Persistence {
    meta:
        description = "Detects scheduled task-based persistence"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1547.010"
        
    strings:
        $pe = "MZ"
        $schtasks = "schtasks.exe" nocase
        $create = "/create" nocase
        $task = "WindowsUpdateClient" nocase
        $wupdater = "wupdater" nocase
        
    condition:
        $pe at 0 and
        $schtasks and
        $create and
        (any of ($task, $wupdater))
}

rule Anti_Analysis_Techniques {
    meta:
        description = "Detects anti-analysis and anti-sandbox techniques"
        author = "Cleanskiier27"
        severity = "medium"
        mitre_technique = "T1057,T1518"
        
    strings:
        $pe = "MZ"
        $debugger = "IsDebuggerPresent" nocase
        $remote_debug = "CheckRemoteDebuggerPresent" nocase
        $vm1 = "VirtualBox" nocase
        $vm2 = "VMware" nocase
        $vm3 = "QEMU" nocase
        
    condition:
        $pe at 0 and
        (any of ($debugger, $remote_debug)) and
        (any of ($vm1, $vm2, $vm3))
}

rule Lateral_Movement_Capability {
    meta:
        description = "Detects lateral movement functionality"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1570"
        
    strings:
        $pe = "MZ"
        $net_apis = "NetConnectEnum" nocase
        $net_share = "NetShareEnum" nocase
        $wmi = "WMI" nocase
        $process_remote = "CreateRemoteThread" nocase
        $service = "StartService" nocase
        
    condition:
        $pe at 0 and
        (any of ($net_apis, $net_share)) and
        (any of ($wmi, $process_remote, $service))
}

rule Encryption_Obfuscation_Routines {
    meta:
        description = "Detects encryption and obfuscation implementations"
        author = "Cleanskiier27"
        severity = "medium"
        mitre_technique = "T1027,T1573"
        
    strings:
        $pe = "MZ"
        $crypt = "CryptEncrypt" nocase
        $aes = "AES" nocase
        $des = "DES" nocase
        $xor_marker = "xor" nocase
        $rc4 = "RC4" nocase
        
    condition:
        $pe at 0 and
        (any of ($crypt, $aes, $des, $rc4)) or
        ($xor_marker and filesize < 500KB)
}

rule DNS_Tunneling_Capability {
    meta:
        description = "Detects DNS tunneling for covert communication"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1071.004"
        
    strings:
        $pe = "MZ"
        $dns_api = "DnsQuery" nocase
        $gethostby = "gethostbyname" nocase
        $txt = "TXT" nocase
        $beacon_domain = "beacon" nocase
        $update_domain = "update" nocase
        
    condition:
        $pe at 0 and
        (any of ($dns_api, $gethostby)) and
        $txt and
        (any of ($beacon_domain, $update_domain))
}

rule Fallback_Channel_Implementation {
    meta:
        description = "Detects multiple C2 fallback channels"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1008"
        
    strings:
        $pe = "MZ"
        $domain1 = "beacon.update-services.net" nocase
        $domain2 = "c2.windowsupdate-sync.com" nocase
        $domain3 = "updatecenter.cloud-monitor.io" nocase
        $https = "https://" nocase
        $http = "http://" nocase
        
    condition:
        $pe at 0 and
        (($domain1 or $domain2 or $domain3)) and
        (#domain1 + #domain2 + #domain3 >= 2)
}

rule Malware_Communication_Protocol {
    meta:
        description = "Detects malware-specific communication protocol patterns"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1095"
        
    strings:
        $pe = "MZ"
        $json_open = "{" 
        $json_cmd = "\"command\""
        $json_beacon = "\"beacon"
        $json_ts = "\"ts\""
        $post = "POST" nocase
        $json_close = "}"
        
    condition:
        $pe at 0 and
        (all of ($json_open, $json_cmd, $json_beacon, $json_ts)) and
        ($post) and
        filesize > 50000
}

rule System_File_Masquerading {
    meta:
        description = "Detects masquerading as legitimate system files"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1036.005"
        
    strings:
        $pe = "MZ"
        $fake_name1 = "wupdater" nocase
        $fake_name2 = "windowsupdate" nocase
        $sys32_path = "\\System32\\" nocase
        $legitimate_api = "RegSetValueEx" nocase
        
    condition:
        $pe at 0 and
        (any of ($fake_name1, $fake_name2)) and
        $sys32_path and
        $legitimate_api
}

rule Multi_Stage_Malware_Loader {
    meta:
        description = "Detects multi-stage malware with DLL injection"
        author = "Cleanskiier27"
        severity = "critical"
        mitre_technique = "T1055"
        
    strings:
        $pe = "MZ"
        $alloc1 = "VirtualAlloc" nocase
        $alloc2 = "VirtualAllocEx" nocase
        $write = "WriteProcessMemory" nocase
        $thread = "CreateRemoteThread" nocase
        $load = "LoadLibrary" nocase
        
    condition:
        $pe at 0 and
        (any of ($alloc1, $alloc2)) and
        $write and
        ($thread or $load)
}

rule Privilege_Escalation_Attempts {
    meta:
        description = "Detects privilege escalation techniques"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1548.002"
        
    strings:
        $pe = "MZ"
        $token = "DuplicateToken" nocase
        $adjust = "AdjustTokenPrivileges" nocase
        $debug_priv = "SeDebugPrivilege" nocase
        $uac_bypass = "fodhelper" nocase
        
    condition:
        $pe at 0 and
        (($token or $adjust) and $debug_priv) or
        $uac_bypass
}

rule Hidden_File_Execution {
    meta:
        description = "Detects files marked as hidden for evasion"
        author = "Cleanskiier27"
        severity = "high"
        mitre_technique = "T1564.001"
        
    strings:
        $pe = "MZ"
        $set_attributes = "SetFileAttributes" nocase
        $hidden = "FILE_ATTRIBUTE_HIDDEN" nocase
        $system32 = "\\System32\\" nocase
        $exe = ".exe" nocase
        
    condition:
        $pe at 0 and
        $set_attributes and
        $system32 and
        $exe
}
