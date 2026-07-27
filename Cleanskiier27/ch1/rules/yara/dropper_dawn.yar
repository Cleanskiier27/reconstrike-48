/*
 * YARA Rule for Dropper Dawn Challenge (Ch1)
 * Detects: Registry-based persistence dropper with Windows Update masquerading
 * Target: Windows PE Executables
 * Confidence: High
 */

rule Dropper_WindowsUpdate_Persistence {
    meta:
        description = "Detects dropper creating registry persistence with WindowsUpdate masquerading"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "high"
        mitre_technique = "T1547.001,T1036.005"
        
    strings:
        // Registry key paths and value names
        $reg_path1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg_path2 = "HKLM" nocase
        $reg_key = "WindowsUpdate" nocase
        
        // Target executable path
        $target_file = "wupdater.exe" nocase
        $target_path = "\\System32\\wupdater" nocase
        
        // API calls for registry manipulation
        $api_reg_create = "RegCreateKeyEx" nocase
        $api_reg_set = "RegSetValueEx" nocase
        $api_reg_open = "RegOpenKeyEx" nocase
        
        // Process creation API
        $api_create_proc = "CreateProcessA" nocase
        $api_shell_exec = "ShellExecute" nocase
        
        // File operations
        $api_create_file = "CreateFileA" nocase
        $api_write_file = "WriteFile" nocase
        
        // Suspicious strings
        $str_update = "update" nocase
        $str_system = "System32" nocase
        $str_windows = "Windows" nocase
        $str_startup = "startup" nocase
        $str_persist = "persist" nocase
        
    condition:
        // PE file detection
        uint16(0) == 0x5a4d and
        
        // Must have at least one registry operation + masquerading
        (($api_reg_create and $api_reg_set) or $api_reg_set) and
        (($reg_path1 and $reg_key) or $target_file) and
        
        // Either targeting Run key or creating wupdater.exe
        (($reg_path1 and $target_file) or $target_path)
}

rule Dropper_Registry_Autorun_Generic {
    meta:
        description = "Generic detection for autorun registry-based droppers"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "high"
        
    strings:
        $pe_header = "MZ"
        $reg_run = "\\CurrentVersion\\Run"
        $api_registry = "RegSetValueEx"
        $api_process = "CreateProcessA"
        
    condition:
        $pe_header at 0 and
        all of ($reg_run, $api_registry, $api_process)
}

rule Dropper_System32_File_Write {
    meta:
        description = "Detects executables writing files to System32 with hidden attributes"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "medium"
        
    strings:
        $pe_header = "MZ"
        $system32_path = "\\System32\\" nocase
        $exe_extension = ".exe" nocase
        $set_attributes = "SetFileAttributes" nocase
        $hidden_attr = 0x02  // FILE_ATTRIBUTE_HIDDEN
        
    condition:
        $pe_header at 0 and
        $system32_path and
        $exe_extension and
        ($set_attributes or $hidden_attr)
}

rule Dropper_UAC_Bypass_Masquerading {
    meta:
        description = "Detects UAC bypass attempts combined with Windows process masquerading"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "high"
        
    strings:
        $pe_header = "MZ"
        
        // UAC bypass techniques
        $fodhelper = "fodhelper" nocase
        $eventvwr = "eventvwr" nocase
        $msiexec = "msiexec" nocase
        
        // Windows process masquerading
        $windows_name = "WindowsUpdate" nocase
        $svc_name = "ServiceHost" nocase
        $wupdater = "wupdater" nocase
        
        // Registry paths for bypass
        $reg_ms = "Microsoft\\Windows" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($fodhelper, $eventvwr, $msiexec)) and
        (any of ($windows_name, $wupdater))
}

rule Dropper_Scheduled_Task_Persistence {
    meta:
        description = "Detects creation of scheduled tasks for persistence with suspicious names"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "medium"
        
    strings:
        $pe_header = "MZ"
        $schtasks = "schtasks.exe" nocase
        $task_create = "/create" nocase
        $task_path = "\\Microsoft\\Windows\\WindowsUpdate" nocase
        $wupdater = "wupdater" nocase
        
    condition:
        $pe_header at 0 and
        $schtasks and
        $task_create and
        ($task_path or $wupdater)
}

rule Dropper_Process_Injection_Setup {
    meta:
        description = "Detects dropper preparing for process injection/DLL loading"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "medium"
        
    strings:
        $pe_header = "MZ"
        $virtual_alloc = "VirtualAllocEx" nocase
        $remote_thread = "CreateRemoteThread" nocase
        $write_process = "WriteProcessMemory" nocase
        $load_library = "LoadLibraryA" nocase
        
    condition:
        $pe_header at 0 and
        (($virtual_alloc and $remote_thread) or
         ($virtual_alloc and $write_process) or
         ($write_process and $remote_thread))
}

rule Dropper_Privilege_Escalation_Pattern {
    meta:
        description = "Detects common privilege escalation patterns used by droppers"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "high"
        
    strings:
        $pe_header = "MZ"
        
        // Token manipulation
        $token_api = "DuplicateToken" nocase
        $adjust_token = "AdjustTokenPrivileges" nocase
        $enable_debug = "SeDebugPrivilege" nocase
        
        // Registry elevation
        $hklm = "HKLM" nocase
        
    condition:
        $pe_header at 0 and
        (($token_api or $adjust_token) and $enable_debug) or
        $hklm
}

rule Dropper_Persistence_Loader {
    meta:
        description = "Generic persistence loader detection combining multiple techniques"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "high"
        
    strings:
        $pe_header = "MZ"
        
        // Persistence mechanisms
        $persistence1 = "\\CurrentVersion\\Run" nocase
        $persistence2 = "Startup" nocase
        $persistence3 = "StartupFolder" nocase
        
        // File operations
        $create_file = "CreateFileA" nocase
        $write_file = "WriteFile" nocase
        
        // Execution
        $exec_api = "CreateProcessA" nocase
        $shell_exec = "ShellExecute" nocase
        
        // Masquerading
        $system32 = "System32" nocase
        $windows = "Windows" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($persistence1, $persistence2, $persistence3)) and
        (any of ($create_file, $write_file)) and
        (any of ($exec_api, $shell_exec)) and
        (any of ($system32, $windows))
}

rule Dropper_AV_Detection_Evasion {
    meta:
        description = "Detects anti-analysis and anti-AV techniques in droppers"
        author = "Cleanskiier27"
        date = "2026-07-27"
        challenge = "ch1-dropper-dawn"
        severity = "medium"
        
    strings:
        $pe_header = "MZ"
        
        // AV process detection
        $kaspersky = "kaspersky" nocase
        $ahnlab = "ahnlab" nocase
        $avast = "avast" nocase
        $bitdefender = "bitdefender" nocase
        $mcafee = "mcafee" nocase
        
        // VM/Sandbox detection
        $vm_check = "vbox" nocase
        $sandbox = "sandbox" nocase
        $wmic = "wmic" nocase
        
        // GetModuleHandle for DLL detection
        $get_module = "GetModuleHandle" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($kaspersky, $ahnlab, $avast, $bitdefender, $mcafee)) and
        $get_module
}
