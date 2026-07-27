/*
 * YARA Rules for Silent Beacon Challenge (Ch2)
 * Detects: Beacon client with C2 communication and command execution capabilities
 * Target: Windows PE Executables and DLLs
 * Confidence: High
 */

rule Beacon_HTTPS_C2_Communication {
    meta:
        description = "Detects beacon establishing HTTPS C2 communication"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "critical"
        mitre_technique = "T1071.001,T1041"
        
    strings:
        // HTTPS connection strings
        $https = "https://" nocase
        $post = "POST" nocase
        $beacon_domain = "beacon.update-services.net" nocase
        $c2_domain = "windowsupdate-sync.com" nocase
        $updatecenter = "updatecenter.cloud-monitor.io" nocase
        
        // API calls for network operations
        $internet_open = "InternetOpenA" nocase
        $internet_connect = "InternetConnectA" nocase
        $http_open = "HttpOpenRequestA" nocase
        $send_request = "HttpSendRequestA" nocase
        
        // JSON indicators for C2 protocol
        $json_check = "\"status\"" nocase
        $json_cmd = "\"command\"" nocase
        $json_beacon = "\"beacon_id\"" nocase
        
    condition:
        uint16(0) == 0x5a4d and
        (any of ($beacon_domain, $c2_domain, $updatecenter)) and
        (any of ($internet_connect, $http_open, $send_request)) and
        any of ($json_check, $json_cmd)
}

rule Beacon_Process_Injection {
    meta:
        description = "Detects beacon performing process injection into svchost"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "critical"
        mitre_technique = "T1055,T1036.005"
        
    strings:
        $pe_header = "MZ"
        
        // Process injection APIs
        $virtual_alloc = "VirtualAllocEx" nocase
        $write_mem = "WriteProcessMemory" nocase
        $create_thread = "CreateRemoteThread" nocase
        
        // Target process
        $svchost = "svchost" nocase
        $services = "services.exe" nocase
        
        // Beacon capability indicators
        $exec_cmd = "exec" nocase
        $upload = "upload" nocase
        $command = "command" nocase
        
    condition:
        $pe_header at 0 and
        all of ($virtual_alloc, $write_mem, $create_thread) and
        any of ($svchost, $services)
}

rule Beacon_Command_Execution {
    meta:
        description = "Detects beacon command execution and exfiltration"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "critical"
        mitre_technique = "T1651,T1041"
        
    strings:
        $pe_header = "MZ"
        
        // Command execution
        $create_process = "CreateProcessA" nocase
        $shell_execute = "ShellExecuteA" nocase
        $cmd_exe = "cmd.exe" nocase
        $powershell = "powershell.exe" nocase
        
        // Exfiltration
        $base64_encode = "CryptEncodeObject" nocase
        $compress = "compress" nocase
        $http_send = "HttpSendRequest" nocase
        
        // Command markers
        $exec_marker = "exec" nocase
        $upload_marker = "upload" nocase
        $download_marker = "download" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($create_process, $shell_execute)) and
        (any of ($base64_encode, $compress)) and
        any of ($exec_marker, $upload_marker, $download_marker)
}

rule Beacon_DNS_Tunnel_Communication {
    meta:
        description = "Detects beacon DNS tunneling fallback communication"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1071.004,T1041"
        
    strings:
        $pe_header = "MZ"
        
        // DNS API calls
        $gethostbyname = "gethostbyname" nocase
        $dns_query = "DnsQuery" nocase
        $resolve = "Resolve" nocase
        
        // TXT record indicators
        $txt_record = "TXT" nocase
        $txt_query = "txt:" nocase
        
        // Beacon domain patterns
        $beacon_tld = "beacon.update-services.net" nocase
        $c2_tld = "c2.windowsupdate-sync.com" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($gethostbyname, $dns_query, $resolve)) and
        (any of ($txt_record, $txt_query)) and
        any of ($beacon_tld, $c2_tld)
}

rule Beacon_Credential_Theft {
    meta:
        description = "Detects beacon capabilities for credential harvesting"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1056,T1005"
        
    strings:
        $pe_header = "MZ"
        
        // Credential APIs
        $cred_enum = "CredEnumerate" nocase
        $logon_sessions = "LsaEnumerateLogonSessions" nocase
        $token_apis = "DuplicateToken" nocase
        
        // Registry credential paths
        $sam_registry = "SAM" nocase
        $lsass = "lsass" nocase
        $credentials = "credentials" nocase
        
        // Memory scraping
        $read_process = "ReadProcessMemory" nocase
        $virtual_query = "VirtualQueryEx" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($cred_enum, $logon_sessions)) and
        (any of ($sam_registry, $lsass))
}

rule Beacon_Anti_Analysis {
    meta:
        description = "Detects beacon anti-analysis and VM detection techniques"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "medium"
        mitre_technique = "T1057,T1518"
        
    strings:
        $pe_header = "MZ"
        
        // Debugger detection
        $kernel_debugger = "kernel debugger" nocase
        $isdebuggerpresent = "IsDebuggerPresent" nocase
        $check_remote = "CheckRemoteDebuggerPresent" nocase
        
        // VM detection
        $vbox = "VirtualBox" nocase
        $vmware = "VMware" nocase
        $hyper_v = "Hyper-V" nocase
        $qemu = "QEMU" nocase
        
        // AV detection
        $antivirus = "antivirus" nocase
        $defender = "windows defender" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($isdebuggerpresent, $check_remote)) and
        (any of ($vbox, $vmware, $hyper_v, $qemu))
}

rule Beacon_Persistence_Setup {
    meta:
        description = "Detects beacon setting up persistence mechanisms"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1547"
        
    strings:
        $pe_header = "MZ"
        
        // Registry persistence
        $reg_run = "\\CurrentVersion\\Run" nocase
        $reg_runonce = "\\CurrentVersion\\RunOnce" nocase
        
        // Scheduled task
        $schtasks = "schtasks" nocase
        $task_create = "/create" nocase
        
        // WMI subscription
        $wmi_event = "WMI" nocase
        $event_consumer = "EventConsumer" nocase
        
        // Startup folder
        $startup = "Startup" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($reg_run, $reg_runonce, $schtasks, $wmi_event, $startup))
}

rule Beacon_Encryption_Routines {
    meta:
        description = "Detects beacon using encryption for C2 communication"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1573"
        
    strings:
        $pe_header = "MZ"
        
        // Crypto APIs
        $crypto_create = "CryptCreateHash" nocase
        $crypto_encrypt = "CryptEncrypt" nocase
        $aes_crypt = "AES" nocase
        $des_crypt = "DES" nocase
        
        // TLS/SSL
        $ssl_context = "SSL_CTX" nocase
        $tls_version = "TLSv1" nocase
        
        // Key derivation
        $pbkdf2 = "PBKDF2" nocase
        $derive_key = "DeriveKey" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($crypto_create, $crypto_encrypt, $aes_crypt)) or
        ($ssl_context and $tls_version)
}

rule Beacon_File_Transfer {
    meta:
        description = "Detects beacon file transfer capabilities"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1105,T1020"
        
    strings:
        $pe_header = "MZ"
        
        // File operations
        $create_file = "CreateFileA" nocase
        $read_file = "ReadFile" nocase
        $write_file = "WriteFile" nocase
        $set_file_ptr = "SetFilePointer" nocase
        
        // Transfer APIs
        $internet_readfile = "InternetReadFile" nocase
        $internet_writefile = "InternetWriteFile" nocase
        
        // Markers
        $download = "download" nocase
        $upload = "upload" nocase
        $transfer = "transfer" nocase
        
    condition:
        $pe_header at 0 and
        (all of ($create_file, $read_file, $write_file)) and
        any of ($download, $upload, $transfer)
}

rule Beacon_Network_Reconnection {
    meta:
        description = "Detects beacon reconnection and failover logic"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1008"
        
    strings:
        $pe_header = "MZ"
        
        // Failover domains
        $primary_domain = "beacon.update-services.net" nocase
        $fallback_domain1 = "c2.windowsupdate-sync.com" nocase
        $fallback_domain2 = "updatecenter.cloud-monitor.io" nocase
        
        // Reconnection logic
        $sleep_api = "Sleep" nocase
        $retry_loop = "retry" nocase
        $backoff = "backoff" nocase
        $interval = "interval" nocase
        
        // Connection APIs
        $connect = "connect" nocase
        $socket = "socket" nocase
        
    condition:
        $pe_header at 0 and
        (($primary_domain and $fallback_domain1) or
         ($primary_domain and $fallback_domain2)) and
        (any of ($sleep_api, $retry_loop, $backoff))
}

rule Beacon_Lateral_Movement {
    meta:
        description = "Detects beacon lateral movement and credential passing"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "high"
        mitre_technique = "T1570,T1550"
        
    strings:
        $pe_header = "MZ"
        
        // Network APIs
        $net_connect = "NetConnectEnum" nocase
        $net_share = "NetShareEnum" nocase
        $net_use = "NetUseAdd" nocase
        
        // Credential passing
        $pass_hash = "PassTheHash" nocase
        $psexec = "PsExec" nocase
        $wmi_connect = "WMI Connect" nocase
        
        // Remote execution
        $remote_proc = "CreateRemoteThread" nocase
        $service_start = "StartService" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($net_connect, $net_share, $net_use)) and
        any of ($pass_hash, $psexec, $wmi_connect)
}

rule Beacon_Discovery_Enumeration {
    meta:
        description = "Detects beacon system and network discovery capabilities"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch2-silent-beacon"
        severity = "medium"
        mitre_technique = "T1518,T1057,T1007"
        
    strings:
        $pe_header = "MZ"
        
        // System enumeration
        $get_system_info = "GetSystemInfo" nocase
        $reg_enum = "RegEnumKeyEx" nocase
        $enum_processes = "EnumProcesses" nocase
        
        // WMI queries
        $wmi_query = "Select" nocase
        $wmi_from = "from Win32" nocase
        
        // Process enumeration
        $toolhelp = "ToolHelp32" nocase
        $createtoolhelp = "CreateToolhelp32Snapshot" nocase
        
        // Service enumeration
        $enum_services = "EnumServices" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($get_system_info, $enum_processes, $createtoolhelp)) and
        (any of ($reg_enum, $wmi_query, $enum_services))
}
