```yara
import "pe"

rule Win64_Qakbot_Loader_BDNIMBUS {
    meta:
        description = "Detects 64-bit Qakbot (Qbot) PE loaders associated with BDNIMBUS campaign v2.7.23"
        author = "Ayush Malwarex"
        date = "2024-04-18"
        last_modified = "2026-08-29"
        version = "1.0"
        malware_family = "Qakbot"
        campaign = "BDNIMBUS"
        hash_reference = "DLLLoader64_B463.exe"
        threat_level = "High"

    strings:
        // Version and campaign build tag hardcoded at OEP
        $ver_str1 = "2.7.23.13110" ascii wide
        $campaign = "26dabe2" ascii wide

        // Configuration probe file
        $ini_config = "Qakbot.ini" wide ascii

        // Stack frame setup preceding VirtualProtect call
        // sub rsp, 0x28 | and dword ptr [rsp+0x30], 0 | lea r9, [rsp+0x30] | mov edx, 0x100
        $op_vprotect_setup = { 48 83 EC 28 83 64 24 30 00 4C 8D 4C 24 30 BA 00 01 00 00 }

        // GetCommandLineA dynamic assignment signature
        // call GetCommandLineA | mov [rel], rax
        $op_getcmdline_a = { FF 15 ?? ?? 00 00 48 89 05 ?? ?? 01 00 }

        // GetCommandLineW dynamic assignment signature
        // call GetCommandLineW | mov [rel], rax
        $op_getcmdline_w = { FF 15 ?? ?? 00 00 48 89 05 ?? ?? 01 00 }

    condition:
        // Ensure 64-bit Windows PE File
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        pe.MACHINE_AMD64 and
        (
            ($ver_str1 and $campaign) or
            ($ini_config and 2 of ($op_*)) or
            all of ($op_*)
        )
}
