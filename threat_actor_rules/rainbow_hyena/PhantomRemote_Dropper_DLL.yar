rule PhantomRemote_Dropper_DLL
{
    meta:
        description = "Detects PhantomRemote DLL with known C2 markers and entry behavior"
        author = "Cyber Graf"
        reference = "BI.ZONE — Rainbow Hyena 2025"
        version = "1.0"
        license = "CC BY 4.0"
        threat_name = "PhantomRemote RAT"

    strings:
        $s1 = "YandexCloud/1.0" ascii
        $s2 = "MicrosoftAppStore/2001.0" ascii
        $s3 = "cmd.exe /u /c" ascii
        $s4 = "poll?id=" ascii
        $s5 = "Download successful:" ascii
        $s6 = "CoCreateGuid" ascii
        $s7 = "GetComputerNameW" ascii
        $s8 = "WINHTTP.dll" ascii
        $dllMarker = "EntryPoint" ascii

    condition:
        uint16(0) == 0x5A4D and 4 of ($s*)
}