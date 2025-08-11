rule CobaltStrike_PowerShell_Base64Loader
{
    meta:
        description = "Detects PowerShell scripts used by Storm-2603 to load Cobalt Strike via base64 and CreateThread"
        author = "Cyber Graf"
        reference = "Check Point Research - Storm-2603’s Previous Ransomware Operations"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "Storm-2603"

    strings:
        $a1 = "FromBase64String" nocase
        $a2 = "VirtualAlloc" nocase
        $a3 = "CreateThread" nocase
        $a4 = "WriteProcessMemory" nocase

    condition:
        all of them
}
