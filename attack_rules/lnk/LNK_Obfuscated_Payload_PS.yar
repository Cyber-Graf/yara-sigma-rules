rule LNK_Obfuscated_Payload_PS
{
    meta:
        description = "Detects LNK files with embedded PowerShell execution and obfuscated payloads"
        author = "Cyber Graf"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "LNK-Embedded-Malware"

    strings:
        $s1 = "FromBase64String" ascii nocase
        $s2 = "Start-Process" ascii nocase
        $s3 = "Select-String" ascii nocase
        $s4 = "cmd.exe /c" ascii
        $s5 = "powershell.exe -e" ascii
        $pe = "TVqQ" ascii  // PE header in overlay
        $htm = "<script" ascii

    condition:
        uint16(0) == 0x4C00 and
        2 of ($s1, $s2, $s3, $s4, $s5) and $pe
}