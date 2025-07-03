rule DireWolf_Ransomware_Dropper
{
    meta:
        description = "Detects Dire Wolf ransomware dropper with shadow copy deletion and config"
        author = "Cyber Graf"
        version = "1.0"
        reference = "Trustwave SpiderLabs, June 2025"
        license = "CC BY 4.0"
        threat_family = "Dire Wolf"

    strings:
        $s1 = "vssadmin delete shadows /all /quiet" ascii
        $s2 = "wmic shadowcopy delete" ascii
        $s3 = "schtasks /create /tn" ascii
        $s4 = ".direwolf" ascii
        $s5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $config = "RC4_KEY=" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
