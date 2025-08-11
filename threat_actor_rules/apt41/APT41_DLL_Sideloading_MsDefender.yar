rule APT41_DLL_Sideloading_MsDefender
{
    meta:
        description = "Detects malicious DLL sideloaded into Microsoft Defender processes"
        author = "Cyber Graf"
        reference = "Securelist, 2025"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "APT41 Loader"

    strings:
        $export1 = "StartW" ascii wide
        $api1 = "VirtualAlloc" ascii
        $api2 = "CreateThread" ascii
        $api3 = "LoadLibraryA" ascii
        $s1 = "MpCmdRun.exe" ascii
        $s2 = "MsMpEng.exe" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($api*) and 1 of ($s1, $s2)
}