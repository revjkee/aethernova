/*
Aethernova Cybersecurity Core — Industrial YARA Ruleset
File: cybersecurity-core/examples/samples/yara_rule.yar
Version: 1.0.0
Requires: YARA 4.x
Refs:
  - YARA docs (syntax, modules): https://yara.readthedocs.io/
  - Neo23x0 YARA Style Guide
*/

import "pe"
import "elf"
import "math"
import "hash"
import "dotnet"
import "time"

private rule AETHERNOVA_IsPE
{
    meta:
        description = "Basic PE magic validation via DOS+NT headers"
        source = "MZ + PE header check"
        version = "1.0.0"
    condition:
        // 'MZ' at 0 and 'PE\0\0' at offset pointed by DWORD at 0x3C
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

private rule AETHERNOVA_IsELF
{
    meta:
        description = "ELF magic validation"
        version = "1.0.0"
    condition:
        // 0x7F 'E' 'L' 'F' big-endian view
        uint32be(0) == 0x7F454C46
}

private rule AETHERNOVA_Has_UPX_Markers
{
    meta:
        description = "Generic UPX indicators (magic/section names)"
        version = "1.0.0"
        tags = "packer,upx"
    strings:
        $upx_magic = "UPX!" ascii
        $sec_upx0  = "UPX0" ascii
        $sec_upx1  = "UPX1" ascii
        $sec_upx2  = "UPX2" ascii
    condition:
        any of them
}

private rule AETHERNOVA_PE_HighEntropy_2PlusSections
{
    meta:
        description = "PE with >=2 high-entropy sections"
        version = "1.0.0"
        threshold = "section entropy > 7.2"
    condition:
        AETHERNOVA_IsPE and
        pe.number_of_sections > 1 and
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].entropy > 7.2 and
                for any j in (0..pe.number_of_sections - 1):
                    ( j != i and pe.sections[j].entropy > 7.2 )
            )
}

private rule AETHERNOVA_PE_SuspiciousImports
{
    meta:
        description = "Suspicious Windows API imports often used for injection/packing"
        version = "1.0.0"
        refs = "pe.imports with regex"
    condition:
        AETHERNOVA_IsPE and
        (
            pe.imports(/kernel32\.dll/i, /(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|LoadLibrary(A|W)?|GetProcAddress)/) or
            pe.imports(/advapi32\.dll/i, /(Reg(Set|Create)Value|Crypt(Acquire|Import)Key)/) or
            pe.imports(/wininet\.dll|winhttp\.dll/i, /(Http(Open|Send|AddRequestHeaders)|WinHttp(Open|Connect|SendRequest))/)
        )
}

private rule AETHERNOVA_Generic_Suspicious_Strings
{
    meta:
        description = "Suspicious strings common in droppers/loaders"
        version = "1.0.0"
    strings:
        $s1 = "powershell -enc" nocase ascii
        $s2 = "FromBase64String" ascii
        $s3 = "AmsiScanBuffer" ascii
        $s4 = /https?:\/\/[a-z0-9\.\-]{3,}\/[^\s"'<>{}]{1,}/ nocase
        $s5 = "rundll32.exe" nocase ascii
    condition:
        #s1 + #s2 + #s3 + #s4 + #s5 >= 2
}

rule AETHERNOVA_PE_Heuristic_Suspicious : pe heuristic triage
{
    meta:
        author = "Aethernova Threat Research"
        description = "PE heuristic triage: entropy/overlay/imports/suspicious strings/time anomalies"
        version = "1.0.0"
        confidence = "medium"
        license = "Apache-2.0"
        tags = "pe,heuristic,triage"
    condition:
        AETHERNOVA_IsPE and
        (
            // whole-file entropy heuristic
            math.entropy(0, filesize) >= 7.2 or
            // >=2 high-entropy sections
            AETHERNOVA_PE_HighEntropy_2PlusSections or
            // overlay present and reasonably large
            pe.overlay.size > 4096 or
            // suspicious imports
            AETHERNOVA_PE_SuspiciousImports or
            // suspicious strings
            AETHERNOVA_Generic_Suspicious_Strings or
            // PE timestamp newer than "now" (clock tamper) or 0
            pe.timestamp == 0 or pe.timestamp > time.now()
        )
}

rule AETHERNOVA_PE_PackerLikely_UPX : pe packer upx
{
    meta:
        author = "Aethernova Threat Research"
        description = "Likely UPX-packed PE (markers/sections/entropy/overlay)"
        version = "1.0.0"
        tags = "pe,packer,upx"
    condition:
        AETHERNOVA_IsPE and
        (
            AETHERNOVA_Has_UPX_Markers or
            pe.overlay.size > 0 or
            math.entropy(0, filesize) >= 7.0
        )
}

rule AETHERNOVA_ELF_Heuristic_Suspicious : elf heuristic triage
{
    meta:
        author = "Aethernova Threat Research"
        description = "ELF heuristic triage: UPX markers and high entropy"
        version = "1.0.0"
        tags = "elf,heuristic,upx"
    condition:
        AETHERNOVA_IsELF and
        (
            AETHERNOVA_Has_UPX_Markers or
            math.entropy(0, filesize) >= 7.0
        )
}

rule AETHERNOVA_DOTNET_Suspicious : dotnet heuristic triage
{
    meta:
        author = "Aethernova Threat Research"
        description = ".NET suspicious markers: P/Invoke to kernel32, PowerShell usage, high entropy"
        version = "1.0.0"
        tags = "dotnet,heuristic"
    strings:
        $ps1 = "System.Management.Automation" ascii
        $ps2 = "PowerShell" ascii
        $pi1 = "kernel32.dll" nocase ascii
        $pi2 = "GetProcAddress" ascii
        $pi3 = "LoadLibrary" ascii
    condition:
        AETHERNOVA_IsPE and dotnet.is_dotnet and
        (
            // P/Invoke hints
            (#pi1 + #pi2 + #pi3) >= 2 or
            // PowerShell embedding
            (#ps1 + #ps2) >= 1 or
            // entropy fallback
            math.entropy(0, filesize) >= 7.0
        )
}

rule AETHERNOVA_File_Known_SHA256_Template : indicator
{
    meta:
        author = "Aethernova Threat Research"
        description = "Template for exact hash match via hash.sha256"
        version = "1.0.0"
        tags = "indicator,hash"
        note = "Replace <SHA256> with a real value when needed"
    condition:
        // Example placeholder; set a real known-bad sample hash to use.
        false or hash.sha256(0, filesize) == "<SHA256>"
}
